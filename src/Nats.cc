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

void makeStringValidKey(std::string& key) {
    size_t pos = 0;
    while ( pos < key.length() ) {
        // TODO: These replacements should not be final, maybe it should just be
        // the hex code or something? Slashes are allowed so like \x55 ish.
        switch ( key.at(pos) ) {
            case '{': key.replace(pos, 1, "LBRACE"); break;
            case '}': key.replace(pos, 1, "RBRACE"); break;
            case ':': key.replace(pos, 1, "COLON"); break;
            case '"': key.replace(pos, 1, "DOUBLEQUOTE"); break;
            case '.': key.replace(pos, 1, "DOT"); break;
            case '*': key.replace(pos, 1, "STAR"); break;
            case '>': key.replace(pos, 1, "GT"); break;
            case '$': key.replace(pos, 1, "DOLLAR"); break;
            case '^': key.replace(pos, 1, "CARROT"); break;
            case ',': key.replace(pos, 1, "COMMA"); break;
            case '[': key.replace(pos, 1, "LBRACKET"); break;
            case ']': key.replace(pos, 1, "RBRACKET"); break;
            case '(': key.replace(pos, 1, "LPAREN"); break;
            case ')': key.replace(pos, 1, "RPAREN"); break;
            case '?': key.replace(pos, 1, "QUESTION"); break;
            case ' ': key.replace(pos, 1, "SPACE"); break;
        }
        pos++;
    }
}

ErrorResult Nats::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    auto json_key = key->ToJSON()->ToStdString();
    makeStringValidKey(json_key);
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
    makeStringValidKey(json_key);
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
