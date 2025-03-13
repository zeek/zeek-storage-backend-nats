# @TEST-DOC: Tests basic successful NATS operations

# @TEST-REQUIRES: have-nats-jetstream
# @TEST-PORT: NATS_PORT

# @TEST-EXEC: cat $FILES/test-server.conf | sed "s|%NATS_PORT%|${NATS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./simple-ops.conf
# @TEST-EXEC: btest-bg-run nats nats-server -c ../simple-ops.conf
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: btest-diff out

@load-plugin Storage::Nats

@load base/frameworks/storage
@load Storage/Nats

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$nats = [ $bucket="TEST_BUCKET", $create_kv=T,
	    $url="nats://localhost:" + getenv("NATS_PORT") ];
	local open_res = Storage::Sync::open_backend(Storage::NATS, opts, string,
	    string);
	if ( open_res$code != Storage::SUCCESS )
		print "Open failed unexpectedly!", open_res;

	local b = open_res$value;

	local put_1 = Storage::Sync::put(b, [ $key="one", $value="val1" ]);
	print "put 1:", put_1;
	local get_1 = Storage::Sync::get(b, "one");
	print "get 1:", get_1;
	local put_2 = Storage::Sync::put(b, [ $key="one", $value="val2" ]);
	print "put 2:", put_2;
	local get_2 = Storage::Sync::get(b, "one");
	print "get 2:", get_2;
	local del_1 = Storage::Sync::erase(b, "one");
	print "del 1:", del_1;

	Storage::Sync::close_backend(b);

	# Now try strict mode!
	local strict_opts: Storage::BackendOptions;
	strict_opts$nats = [ $bucket="TEST_BUCKET", $create_kv=T,
	    $url="nats://localhost:" + getenv("NATS_PORT"), $strict=T ];
	local strict_open_res = Storage::Sync::open_backend(Storage::NATS, strict_opts,
	    string, string);
	if ( strict_open_res$code != Storage::SUCCESS )
		print "Open failed unexpectedly!", strict_open_res;

	local strict_b = strict_open_res$value;

	local strict_put_1 = Storage::Sync::put(strict_b, [ $key="strict_one",
	    $value="strict_val1" ]);
	print "strict_put 1:", strict_put_1;
	local strict_get_1 = Storage::Sync::get(strict_b, "strict_one");
	print "strict_get 1:", strict_get_1;
	local strict_put_2 = Storage::Sync::put(strict_b, [ $key="strict_one",
	    $value="strict_val2" ]);
	print "strict_put 2:", strict_put_2;
	local strict_get_2 = Storage::Sync::get(strict_b, "strict_one");
	print "strict_get 2:", strict_get_2;
	local strict_del_1 = Storage::Sync::erase(strict_b, "strict_one");
	print "strict_del 1:", strict_del_1;

	Storage::Sync::close_backend(strict_b);
	}
