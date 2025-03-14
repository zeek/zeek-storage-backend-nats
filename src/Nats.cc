#include "Nats.h"

#include <nats/nats.h>
#include <storage/Backend.h>
#include <zeek/Func.h>
#include <zeek/ZeekString.h>
#include <zeek/storage/ReturnCode.h>
#include <zeek/util.h>

namespace zeek::storage::backends::nats {

OperationResult Nats::DoOpen(OpenResultCallback* cb, RecordValPtr options) {
    RecordValPtr config = options->GetField<RecordVal>("nats");
    strict = config->GetField<BoolVal>("strict")->Get();
    if ( strict && key_type->Tag() != TYPE_STRING )
        return {ReturnCode::CONNECTION_FAILED,
                util::fmt("NATS strict mode can only have string keys, found '%s'", key_type->GetName().c_str())};

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
        return {ReturnCode::CONNECTION_FAILED, natsStatus_GetText(stat)};

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
        return {ReturnCode::CONNECTION_FAILED, natsStatus_GetText(stat)};

    kvConfig kvc;
    stat = kvConfig_Init(&kvc);
    if ( stat != NATS_OK )
        return {ReturnCode::CONNECTION_FAILED, natsStatus_GetText(stat)};

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
        return {ReturnCode::CONNECTION_FAILED, natsStatus_GetText(stat)};

    if ( config->HasField("expiration_prefix") )
        expiration_prefix = config->GetField<StringVal>("expiration_prefix")->Get()->CheckString();

    if ( expiration_prefix.empty() )
        return {ReturnCode::CONNECTION_FAILED, "Expiration prefix cannot be empty; omit the field for default"};


    return {ReturnCode::SUCCESS};
}

OperationResult Nats::DoClose(OperationResultCallback* cb) {
    kvStore_Destroy(key_val);
    jsCtx_Destroy(jetstream);
    natsConnection_Destroy(conn);
    nats_Close();

    conn = nullptr;
    jetstream = nullptr;
    key_val = nullptr;

    return {ReturnCode::SUCCESS};
}

std::string make_string_valid_key(std::string_view key) {
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

std::string Nats::KeyFromVal(ValPtr key) {
    if ( strict ) {
        assert(key_type->Tag() == TYPE_STRING && "Key type must be strings in strict mode");
        return key->AsStringVal()->Get()->CheckString();
    }
    else {
        auto json_key = key->ToJSON()->ToStdString();
        return make_string_valid_key(json_key);
    }
}


OperationResult Nats::DoPut(OperationResultCallback* cb, ValPtr key, ValPtr value, bool overwrite,
                            double expiration_time) {
    auto key_string = KeyFromVal(key);
    auto json_value = value->ToJSON()->ToStdString();
    uint64_t rev = 0;

    natsStatus stat;
    if ( overwrite )
        stat = kvStore_PutString(&rev, key_val, key_string.c_str(), json_value.c_str());
    else
        stat = kvStore_CreateString(&rev, key_val, key_string.c_str(), json_value.c_str());

    if ( stat != NATS_OK )
        return {ReturnCode::OPERATION_FAILED, util::fmt("Put operation failed: %s", natsStatus_GetText(stat))};

    // TODO: Probably sort these somehow?
    if ( expiration_time > 0.0 ) {
        std::string exp_string = util::fmt("%f", expiration_time);
        stat = kvStore_PutString(&rev, key_val, util::fmt("%s.%s", expiration_prefix.c_str(), key_string.c_str()),
                                 exp_string.c_str());
    }

    return {ReturnCode::SUCCESS};
}

OperationResult Nats::DoGet(OperationResultCallback* cb, ValPtr key) {
    kvEntry* entry = nullptr;
    auto key_string = KeyFromVal(key);
    auto stat = kvStore_Get(&entry, key_val, key_string.c_str());
    if ( stat != NATS_OK )
        return {ReturnCode::OPERATION_FAILED, util::fmt("Get operation failed: %s", natsStatus_GetText(stat))};

    // Extract the string
    auto retrieved = kvEntry_ValueString(entry);
    OperationResult res = {ReturnCode::OPERATION_FAILED};
    auto val = zeek::detail::ValFromJSON(retrieved, val_type, Func::nil);

    if ( std::holds_alternative<ValPtr>(val) ) {
        ValPtr val_v = std::get<ValPtr>(val);
        res = {ReturnCode::SUCCESS, "", val_v};
    }

    if ( res.code != ReturnCode::SUCCESS )
        res.err_str = std::get<std::string>(val);

    kvEntry_Destroy(entry);
    return res;
}

OperationResult Nats::DoErase(OperationResultCallback* cb, ValPtr key) {
    auto json_key = key->ToJSON()->ToStdString();
    auto key_string = KeyFromVal(key);

    auto stat = kvStore_Delete(key_val, key_string.c_str());
    if ( stat != NATS_OK )
        return {ReturnCode::OPERATION_FAILED, natsStatus_GetText(stat)};

    stat = kvStore_Delete(key_val, util::fmt("%s.%s", expiration_prefix.c_str(), key_string.c_str()));
    // Erase failure of expiration is ok maybe

    return {ReturnCode::SUCCESS};
}

void Nats::DoExpire(double current_network_time) {
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

        if ( current_network_time > expiration_time ) {
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
