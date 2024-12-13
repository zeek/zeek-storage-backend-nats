#include "Nats.h"

namespace zeek::storage::backends::nats {

// TODO
ErrorResult Nats::DoOpen(RecordValPtr config) { return std::nullopt; }

// TODO
void Nats::Done() {}

// TODO
ErrorResult Nats::DoPut(ValPtr key, ValPtr value, bool overwrite, double expiration_time, ErrorResultCallback* cb) {
    return std::nullopt;
}

// TODO
ValResult Nats::DoGet(ValPtr key, ValResultCallback* cb) { return nonstd::unexpected<std::string>(""); }

// TODO
ErrorResult Nats::DoErase(ValPtr key, ErrorResultCallback* cb) { return std::nullopt; }
} // namespace zeek::storage::backends::nats
