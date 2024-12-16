// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <nats/nats.h>
#include <zeek/iosource/IOSource.h>
#include <zeek/storage/Backend.h>

namespace zeek::storage::backends::nats {

class Nats : public zeek::storage::Backend, public iosource::IOSource {
public:
    Nats() : Backend(true), IOSource(true) {}

    static Backend* Instantiate() { return new Nats(); }
    const char* Tag() override { return "NatsStorage"; }
    bool IsOpen() override { return connected; }
    void Done() override;
    ErrorResult DoOpen(RecordValPtr config) override;
    ErrorResult DoPut(ValPtr key, ValPtr value, bool overwrite = true, double expiration_time = 0,
                      ErrorResultCallback* cb = nullptr) override;
    ValResult DoGet(ValPtr key, ValResultCallback* cb = nullptr) override;
    ErrorResult DoErase(ValPtr key, ErrorResultCallback* cb = nullptr) override;

    // IOSource interface
    double GetNextTimeout() override { return -1; }
    void Process() override {}

private:
    bool connected = false;
    natsConnection* conn = nullptr;
    kvStore* keyVal = nullptr;
};
} // namespace zeek::storage::backends::nats
