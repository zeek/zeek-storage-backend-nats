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
    // like 50 options.
    stat = natsConnection_ConnectTo(&conn, url->CheckString());
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    jsOptions jsOpts;
    jsOptions_Init(&jsOpts);
    jsOpts.PublishAsync.MaxPending = 256;

    // Create JetStream Context
    // TODO: Figure out what if this I need to free memory from etc.
    jsCtx* js = nullptr;
    natsConnection_JetStream(&js, conn, &jsOpts);

    kvConfig kvc;
    kvConfig_Init(&kvc);

    kvc.Bucket = "KVS2";
    kvc.History = 10;

    stat = js_CreateKeyValue(&keyVal, js, &kvc);
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    return std::nullopt;
}

// TODO: Destroy jetstream too?
void Nats::Done() {
    natsConnection_Destroy(conn);
    kvStore_Destroy(keyVal);
    conn = nullptr;
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

    auto stat = kvStore_PutString(&rev, keyVal, valid_key.c_str(), json_value.c_str());
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
