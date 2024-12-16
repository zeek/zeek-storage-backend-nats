#include "Nats.h"

#include <nats/nats.h>
#include <zeek/Func.h>

namespace zeek::storage::backends::nats {

ErrorResult Nats::DoOpen(RecordValPtr config) {
    natsConnection* conn = nullptr;
    natsStatus stat;

    // TODO: Not default URL, let that configure via config
    stat = natsConnection_ConnectTo(&conn, NATS_DEFAULT_URL);
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

    connected = true;
    return std::nullopt;
}

// TODO: Destroy jetstream too?
void Nats::Done() {
    natsConnection_Destroy(conn);
    kvStore_Destroy(keyVal);
}

ErrorResult Nats::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    // TODO: The key needs special escaping, namely to avoid `null` (I think that means ASCII 0?),
    // space, '.', '*', and '>'
    // Also can't start with a star or underscore, by convention
    // But... it seems to apply to curly braces and stuff too. :(
    auto json_key = key->ToJSON()->ToStdString();
    auto json_value = value->ToJSON()->ToStdString();
    uint64_t rev = 0;

    auto stat = kvStore_PutString(&rev, keyVal, json_key.c_str(), json_value.c_str());
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    return std::nullopt;
}

ValResult Nats::DoGet(ValPtr key, ValResultCallback* cb) {
    kvEntry* entry = NULL;
    auto json_key = key->ToJSON()->ToStdString();
    auto stat = kvStore_Get(&entry, keyVal, json_key.c_str());
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

    auto stat = kvStore_Delete(keyVal, json_key.c_str());
    if ( stat != NATS_OK )
        return natsStatus_GetText(stat);

    return std::nullopt;
}
} // namespace zeek::storage::backends::nats
