
#include "Plugin.h"

namespace plugin { namespace Storage_Nats { Plugin plugin; } }

using namespace plugin::Storage_Nats;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Storage::Nats";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
