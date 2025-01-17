#include "Nats.h"

#include <nats/nats.h>
#include <zeek/Func.h>
#include <zeek/ZeekString.h>
#include <zeek/util.h>

#include <iostream>

namespace zeek::storage::backends::nats {

ErrorResult Nats::DoOpen(RecordValPtr config) {
    auto url = config->GetField<StringVal>("url")->Get();
    natsStatus stat;

    natsOptions* nats_opts;
    natsOptions_Create(&nats_opts);
    natsOptions_SetURL(nats_opts, url->CheckString());
    if ( config->HasField("creds") )
        natsOptions_SetUserCredentialsFromFiles(nats_opts, config->GetField<StringVal>("creds")->Get()->CheckString(),
                                                nullptr);
    stat = natsConnection_Connect(&conn, nats_opts);
    natsOptions_Destroy(nats_opts);
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    jsOptions js_opts;
    jsOptions_Init(&js_opts);
    // TODO: When async is done this should be an option, also look at other
    // async options
    js_opts.PublishAsync.MaxPending = 256;

    if ( config->HasField("jetstream_prefix") )
        js_opts.Prefix = config->GetField<StringVal>("jetstream_prefix")->Get()->CheckString();
    if ( config->HasField("jetstream_domain") )
        js_opts.Domain = config->GetField<StringVal>("jetstream_domain")->Get()->CheckString();
    if ( config->HasField("wait") )
        js_opts.Wait = config->GetField<IntVal>("wait")->Get();

    // Create JetStream Context
    stat = natsConnection_JetStream(&jetstream, conn, &js_opts);
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    jsStreamInfo* si = nullptr;

    // First check if the stream already exists.
    stat = js_GetStreamInfo(&si, jetstream, "zeek", nullptr, nullptr);
    if ( stat == NATS_NOT_FOUND ) {
        jsErrCode jerr;
        jsStreamConfig cfg;
        jsStreamConfig_Init(&cfg);
        cfg.Name = "zeek";
        auto subject = "zeek.expire.*";
        cfg.Subjects = (const char* [1]){subject};
        cfg.SubjectsLen = 1;
        cfg.MaxBytes = 1000;
        stat = js_AddStream(&si, jetstream, &cfg, nullptr, &jerr);
        if ( jerr != 0 )
            return util::fmt("Creating Jetstream stream failed with error code %d", jerr);
    }

    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    kvConfig kvc;
    stat = kvConfig_Init(&kvc);
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    kvc.Bucket = config->GetField<StringVal>("bucket")->Get()->CheckString();

    if ( config->HasField("bucket_max_size") )
        kvc.MaxBytes = config->GetField<CountVal>("bucket_max_size")->Get();

    if ( config->HasField("value_max_size") )
        kvc.MaxValueSize = config->GetField<CountVal>("value_max_size")->Get();

    if ( config->HasField("ttl") )
        kvc.MaxValueSize = config->GetField<CountVal>("ttl")->Get();

    if ( config->GetField<BoolVal>("create_kv")->Get() )
        stat = js_CreateKeyValue(&keyVal, jetstream, &kvc);
    else
        stat = js_KeyValue(&keyVal, jetstream, kvc.Bucket);
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    return std::nullopt;
}

void Nats::Done() {
    kvStore_Destroy(keyVal);
    jsCtx_Destroy(jetstream);
    natsConnection_Destroy(conn);
    nats_Close();

    conn = nullptr;
    jetstream = nullptr;
    keyVal = nullptr;
}

std::string makeStringValidKey(std::string_view key) {
    std::string result;

    for ( auto c : key ) {
        if ( std::isalnum(c) ) {
            result += c;
        }
        else {
            char buf[5];
            // Ignore smaller write, it doesn't really matter for now
            snprintf(buf, sizeof(buf), "\\x%02X", static_cast<unsigned char>(c));
            result += buf;
        }
    }

    return result;
}

ErrorResult Nats::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);
    auto json_value = value->ToJSON()->ToStdString();
    uint64_t rev = 0;

    natsStatus stat;
    if ( overwrite )
        stat = kvStore_PutString(&rev, keyVal, valid_key.c_str(), json_value.c_str());
    else
        stat = kvStore_CreateString(&rev, keyVal, valid_key.c_str(), json_value.c_str());

    // TODO: If a key exists, the GetText result is just "Error" because
    // stat == NATS_ERR. That's pretty unintuitive, but I'd also be worried that
    // catching that error means we catch more than we want. So may have to check
    // if the key exists manually before putting it, rather than using Put/Create
    // based on `overwrite`
    if ( stat != NATS_OK )
        return util::fmt("Put operation failed: %s", natsStatus_GetText(stat));

    if ( expiration_time > 0.0 ) {
        std::string exp_string = util::fmt("%f", expiration_time);
        jsErrCode jerr;
        stat = js_Publish(nullptr, jetstream, util::fmt("zeek.expire.%s", valid_key.c_str()), exp_string.c_str(),
                          exp_string.length(), nullptr, &jerr);
        if ( jerr != 0 )
            return util::fmt("Publishing to Jetstream stream failed with error code %d", jerr);
        if ( stat != NATS_OK )
            return util::fmt("Put operation succeeded, but expiration stream failed: %s", natsStatus_GetText(stat));
    }

    return std::nullopt;
}

ValResult Nats::DoGet(ValPtr key, ValResultCallback* cb) {
    kvEntry* entry = NULL;
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);
    auto stat = kvStore_Get(&entry, keyVal, valid_key.c_str());
    if ( stat != NATS_OK )
        return nonstd::unexpected<std::string>(util::fmt("Get operation failed: %s", natsStatus_GetText(stat)));

    // Extract the string
    auto retrieved = kvEntry_ValueString(entry);
    ValResult res;
    auto val = zeek::detail::ValFromJSON(retrieved, val_type, Func::nil);

    if ( std::holds_alternative<ValPtr>(val) ) {
        ValPtr val_v = std::get<ValPtr>(val);
        res = val_v;
    }

    if ( ! res )
        res = nonstd::unexpected<std::string>(std::get<std::string>(val));

    return res;
}

ErrorResult Nats::DoErase(ValPtr key, ErrorResultCallback* cb) {
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);

    auto stat = kvStore_Delete(keyVal, valid_key.c_str());
    if ( stat != NATS_OK )
        return util::fmt("Erase operation failed: %s", natsStatus_GetText(stat));

    return std::nullopt;
}

void Nats::Expire() {}
} // namespace zeek::storage::backends::nats
