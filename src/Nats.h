// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <zeek/storage/Backend.h>

namespace zeek::storage::backends::nats {

class Nats : public zeek::storage::Backend {
public:
    Nats() : Backend(false) {}

    static Backend* Instantiate() { return new Nats(); }
    const char* Tag() override { return "NatsStorage"; }
    bool IsOpen() override { return conn != nullptr; }
    ErrorResult DoOpen(RecordValPtr config, OpenResultCallback* cb = nullptr) override;
    ErrorResult DoDone(ErrorResultCallback* cb = nullptr) override;
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr) override;
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    void Expire() override;

private:
    std::string KeyFromVal(ValPtr key);

    natsConnection* conn = nullptr;
    jsCtx* jetstream = nullptr;
    kvStore* key_val = nullptr;
    std::string expiration_prefix = "";
    bool strict;
};
} // namespace zeek::storage::backends::nats
