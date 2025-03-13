# @TEST-DOC: Tests basic successful NATS operations

# @TEST-REQUIRES: have-nats-jetstream
# @TEST-PORT: NATS_PORT

# @TEST-EXEC: cat $FILES/test-server.conf | sed "s|%NATS_PORT%|${NATS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./expire.conf
# @TEST-EXEC: btest-bg-run nats nats-server -c ../expire.conf
# @TEST-EXEC: zeek -Cr $TRACES/set.pcap %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: btest-diff out

@load base/frameworks/storage
@load Storage/Nats

redef Storage::expire_interval = 2secs;
redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;

event check_removed()
	{
	local res1 = Storage::Sync::get(b, "expires");
	# TODO: Fix expiration, this doesn't work
	if ( res1$code != Storage::SUCCESS )
		print "get1", res1;
	else
		print "get1 succeeded unexpectedly!";

	local res2 = Storage::Sync::get(b, "noexpire");
	if ( res2$code != Storage::SUCCESS )
		print "get2 failed unexpectedly!", res2;
	else
		print "get2", res2;
	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$nats = [ $bucket="abucket", $create_kv=T,
	    $url="nats://localhost:" + getenv("NATS_PORT") ];
	local open_res = Storage::Sync::open_backend(Storage::NATS, opts, string,
	    string);
	if ( open_res$code != Storage::SUCCESS )
		print "Open failed unexpectedly!", open_res;

	b = open_res$value;

	local put1 = Storage::Sync::put(b, [ $key="expires", $value="efgh",
	    $expire_time=2secs ]);
	print "put1", put1;
	local put2 = Storage::Sync::put(b, [ $key="noexpire", $value="1234",
	    $expire_time=15secs ]);
	print "put2", put2;

	local get1 = Storage::Sync::get(b, "expires");
	print "get1", get1;
	local get2 = Storage::Sync::get(b, "noexpire");
	print "get2", get2;

	schedule 5secs { check_removed() };
	}

event zeek_init()
	{
	schedule 100msecs { setup_test() };
	}
