
#include <nats/nats.h>

#include "Plugin.h"

namespace plugin {
namespace Storage_Nats {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::Storage_Nats;

zeek::plugin::Configuration Plugin::Configure() {
  zeek::plugin::Configuration config;
  config.name = "Storage::Nats";
  config.description = "A NATS backend for key/value stores";
  config.version.major = 0;
  config.version.minor = 1;
  config.version.patch = 0;

  // EXPERIMENT TIME
  natsConnection *conn = NULL;
  natsOptions *opts = NULL;
  natsConnection_Connect(&conn, opts);

  // Initialize and set some JetStream options
  jsOptions jsOpts;
  jsOptions_Init(&jsOpts);
  jsOpts.PublishAsync.MaxPending = 256;

  // Create JetStream Context
  jsCtx *js = NULL;
  kvStore *kv = NULL;
  kvConfig kvc;

  natsConnection_JetStream(&js, conn, &jsOpts);

  // Assume we got a JetStream context in `js`...

  kvConfig_Init(&kvc);
  kvc.Bucket = "KVS";
  kvc.History = 10;
  natsStatus s = js_CreateKeyValue(&kv, js, &kvc);

  // Do some stuff...

  // This is to free the memory used by `kv` object,
  // not delete the KeyValue store in the server
  uint64_t rev = 0;

  // Assume we got a kvStore...

  s = kvStore_PutString(&rev, kv, "MY_KEY", "my value");

  // If the one does not care about getting the revision, pass NULL:
  s = kvStore_PutString(NULL, kv, "MY_KEY", "my value");

  kvStore_Destroy(kv);
  return config;
}
