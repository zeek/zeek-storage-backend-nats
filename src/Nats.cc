#include "Nats.h"

#include <nats/nats.h>
#include <zeek/Func.h>
#include <zeek/ZeekString.h>

namespace zeek::storage::backends::nats {

ErrorResult Nats::DoOpen(RecordValPtr config) {
    auto url = config->GetField<StringVal>("url")->Get();
    natsStatus stat;

    // TODO: If I'm being thorough, this would be a `natsConnection_Connect` call
    // and the record would have all of the `__natsOptions` options. But there are
    // like 50 options. This would then later call `natsOptions_Destroy`
    stat = natsConnection_ConnectTo(&conn, url->CheckString());
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    jsOptions jsOpts;
    jsOptions_Init(&jsOpts);
    jsOpts.PublishAsync.MaxPending = 256;

    // Create JetStream Context
    natsConnection_JetStream(&jetstream, conn, &jsOpts);

    kvConfig kvc;
    kvConfig_Init(&kvc);

    kvc.Bucket = config->GetField<StringVal>("bucket")->Get()->CheckString();

    if ( config->HasField("bucket_max_size") )
        kvc.MaxBytes = config->GetField<CountVal>("bucket_max_size")->Get();

    if ( config->HasField("value_max_size") )
        kvc.MaxValueSize = config->GetField<CountVal>("value_max_size")->Get();

    if ( config->HasField("ttl") )
        kvc.MaxValueSize = config->GetField<CountVal>("ttl")->Get();

    stat = js_CreateKeyValue(&keyVal, jetstream, &kvc);
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
            snprintf(buf, sizeof(buf), "\\x%02X", c);
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
        return natsStatus_GetText(stat);

    return std::nullopt;
}

ValResult Nats::DoGet(ValPtr key, ValResultCallback* cb) {
    kvEntry* entry = NULL;
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);
    auto stat = kvStore_Get(&entry, keyVal, valid_key.c_str());
    if ( stat != NATS_OK )
        return nonstd::unexpected<std::string>(natsStatus_GetText(stat));

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
        return natsStatus_GetText(stat);

    return std::nullopt;
}
} // namespace zeek::storage::backends::nats
