#include "Plugin.h"

#include <nats/nats.h>
#include <zeek/storage/Component.h>

#include "Nats.h"

namespace zeek::storage::backend::nats {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new storage::Component("NATS", zeek::storage::backends::nats::Nats::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Storage::Nats";
    config.description = "Nats backend for storage framework";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
}
} // namespace zeek::storage::backend::nats
