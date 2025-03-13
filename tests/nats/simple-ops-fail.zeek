# @TEST-DOC: Tests basic successful NATS operations

# @TEST-REQUIRES: have-nats-jetstream
# @TEST-PORT: NATS_PORT

# @TEST-EXEC: cat $FILES/test-server.conf | sed "s|%NATS_PORT%|${NATS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./simple-ops-fail.conf
# @TEST-EXEC: btest-bg-run nats nats-server -config ../simple-ops-fail.conf
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

@load-plugin Storage::Nats

@load base/frameworks/storage
@load Storage/Nats

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$nats = [ $bucket="abucket", $create_kv=T,
	    $url="nats://localhost:" + getenv("NATS_PORT") ];
	local open_res = Storage::Sync::open_backend(Storage::NATS, opts, string,
	    string);
	if ( open_res$code != Storage::SUCCESS )
		print "Open failed unexpectedly!", open_res;

	local b = open_res$value;

	local put_1 = Storage::Sync::put(b, [ $key="one", $value="val1" ]);
	print "put 1:", put_1;
	# Put with no overwrite should fail
	local put_2 = Storage::Sync::put(b, [ $key="one", $value="val2", $overwrite=F ]);
	print "put 2:", put_2;
	local del_1 = Storage::Sync::erase(b, "one");
	print "del 1:", del_1;
	# Get after deletion should fail
	local get_1 = Storage::Sync::get(b, "one");
	print "get 1:", get_1;

	Storage::Sync::close_backend(b);

	local strict_opts: Storage::BackendOptions;
	strict_opts$nats = [ $bucket="abucket", $create_kv=T,
	    $url="nats://localhost:" + getenv("NATS_PORT"), $strict=T ];
	# Strict cannot have a non-string key
	local strict_res = Storage::Sync::open_backend(Storage::NATS, strict_opts,
	    port, string);
	if ( strict_res$code == Storage::SUCCESS )
		print "Opening in strict mode failed unexpectedly!";
	else
		print strict_res$error_str;
	}
