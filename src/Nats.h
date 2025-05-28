// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <zeek/storage/Backend.h>

namespace zeek::storage::backends::nats {

class Nats : public Backend {
public:
    Nats() : Backend(SupportedModes::SYNC, "NATS") {}
    ~Nats() override = default;

    static storage::BackendPtr Instantiate();

    bool IsOpen() override { return conn != nullptr; }
    OperationResult DoOpen(OpenResultCallback* cb, RecordValPtr options) override;
    OperationResult DoClose(ResultCallback* cb) override;
    OperationResult DoPut(ResultCallback* cb, ValPtr key, ValPtr value, bool overwrite = true,
                          double expiration_time = 0) override;
    OperationResult DoGet(ResultCallback* cb, ValPtr key) override;
    OperationResult DoErase(ResultCallback* cb, ValPtr key) override;

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
