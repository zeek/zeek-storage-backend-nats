// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <zeek/storage/Backend.h>

namespace zeek::storage::backends::nats {

class Nats : public Backend {
public:
    Nats(std::string_view tag) : Backend(SupportedModes::SYNC, tag) {}

    static storage::BackendPtr Instantiate(std::string_view tag) { return make_intrusive<Nats>(tag); }
    // const char* Tag() override { return tag.c_str(); }
    bool IsOpen() override { return conn != nullptr; }
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(OperationResultCallback* cb) override;
    OperationResult DoPut(OperationResultCallback* cb, ValPtr key, ValPtr value, bool overwrite = true,
                          double expiration_time = 0) override;
    OperationResult DoGet(OperationResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(OperationResultCallback* cb, ValPtr key) override;

    void DoExpire(double current_network_time) override;

private:
    std::string KeyFromVal(ValPtr key);

    natsConnection* conn = nullptr;
    jsCtx* jetstream = nullptr;
    kvStore* key_val = nullptr;
    std::string expiration_prefix = "";
    bool strict;
};
} // namespace zeek::storage::backends::nats
