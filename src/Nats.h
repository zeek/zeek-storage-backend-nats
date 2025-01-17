// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <zeek/storage/Backend.h>

namespace zeek::storage::backends::nats {

class Nats : public zeek::storage::Backend {
public:
    Nats() : Backend(true) {}

    static Backend* Instantiate() { return new Nats(); }
    const char* Tag() override { return "NatsStorage"; }
    bool IsOpen() override { return conn != nullptr; }
    void Done() override;
    ErrorResult DoOpen(RecordValPtr config) override;
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr) override;
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    void Expire() override;

private:
    natsConnection* conn = nullptr;
    jsCtx* jetstream = nullptr;
    kvStore* keyVal = nullptr;
    natsSubscription* expiration_consumer = nullptr;
};
} // namespace zeek::storage::backends::nats
