#include "Nats.h"

#include <nats/nats.h>
#include <storage/Backend.h>
#include <zeek/Func.h>
#include <zeek/ZeekString.h>
#include <zeek/util.h>

namespace zeek::storage::backends::nats {

ErrorResult Nats::DoOpen(RecordValPtr config, OpenResultCallback* cb) {
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

    if ( config->HasField("wait") )
        js_opts.Wait = config->GetField<IntVal>("wait")->Get();

    // Create JetStream Context
    stat = natsConnection_JetStream(&jetstream, conn, &js_opts);
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
        stat = js_CreateKeyValue(&key_val, jetstream, &kvc);
    else
        stat = js_KeyValue(&key_val, jetstream, kvc.Bucket);

    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    if ( config->HasField("expiration_prefix") )
        expiration_prefix = config->GetField<StringVal>("expiration_prefix")->Get()->CheckString();

    if ( expiration_prefix.empty() )
        return "Expiration prefix cannot be empty; omit the field for default";


    return std::nullopt;
}

ErrorResult Nats::DoDone(ErrorResultCallback* cb) {
    kvStore_Destroy(key_val);
    jsCtx_Destroy(jetstream);
    natsConnection_Destroy(conn);
    nats_Close();

    conn = nullptr;
    jetstream = nullptr;
    key_val = nullptr;

    return std::nullopt;
}

std::string makeStringValidKey(std::string_view key) {
    std::string result;

    for ( auto c : key ) {
        if ( std::isalnum(c) )
            result += c;
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
        stat = kvStore_PutString(&rev, key_val, valid_key.c_str(), json_value.c_str());
    else
        stat = kvStore_CreateString(&rev, key_val, valid_key.c_str(), json_value.c_str());

    // Workaround: If the key exists and overwrite is false, the error is just "Error"
    // Add a custom error to make it more user-friendly, but with an extra request.
    if ( stat == NATS_ERR && ! overwrite ) {
        kvEntry* entry = nullptr;
        stat = kvStore_Get(&entry, key_val, valid_key.c_str());
        if ( stat == NATS_OK && entry != nullptr )
            return "Put operation failed: Key exists and overwrite not set";
    }

    if ( stat != NATS_OK )
        return util::fmt("Put operation failed: %s", natsStatus_GetText(stat));

    // TODO: Probably sort these somehow?
    if ( expiration_time > 0.0 ) {
        std::string exp_string = util::fmt("%f", expiration_time + run_state::network_time);
        stat = kvStore_PutString(&rev, key_val, util::fmt("%s.%s", expiration_prefix.c_str(), valid_key.c_str()),
                                 exp_string.c_str());
    }

    return std::nullopt;
}

ValResult Nats::DoGet(ValPtr key, ValResultCallback* cb) {
    kvEntry* entry = nullptr;
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);
    auto stat = kvStore_Get(&entry, key_val, valid_key.c_str());
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

    kvEntry_Destroy(entry);
    return res;
}

ErrorResult Nats::DoErase(ValPtr key, ErrorResultCallback* cb) {
    auto json_key = key->ToJSON()->ToStdString();
    auto valid_key = makeStringValidKey(json_key);

    auto stat = kvStore_Delete(key_val, valid_key.c_str());
    if ( stat != NATS_OK )
        return util::fmt("Erase operation failed: %s", natsStatus_GetText(stat));

    stat = kvStore_Delete(key_val, util::fmt("%s.%s", expiration_prefix.c_str(), valid_key.c_str()));
    // Erase failure of expiration is ok maybe

    return std::nullopt;
}

void Nats::Expire() {
    kvKeysList keys;
    std::string subject = util::fmt("%s.*", expiration_prefix.c_str());
    const char* subject_arr[] = {subject.c_str()};
    kvStore_KeysWithFilters(&keys, key_val, subject_arr, 1, nullptr);

    kvEntry* entry = nullptr;
    for ( int i = 0; i < keys.Count; i++ ) {
        auto key = keys.Keys[i];
        auto stat = kvStore_Get(&entry, key_val, key);
        if ( stat != NATS_OK )
            continue;

        // Extract the string
        auto retrieved = kvEntry_ValueString(entry);
        float expiration_time;
        try {
            expiration_time = std::stof(retrieved);
        } catch ( ... ) {
            continue;
        }

        if ( run_state::network_time > expiration_time ) {
            stat = kvStore_Delete(key_val, key);
            // If we (somehow) have a key that's too short, abort here
            if ( strlen(key) <= expiration_prefix.length() + 1 )
                continue;
            // Everything after expiration_prefix plus dot is the value's normal key
            stat = kvStore_Delete(key_val, &key[expiration_prefix.length() + 1]);
        }
    }

    kvKeysList_Destroy(&keys);
}
} // namespace zeek::storage::backends::nats
