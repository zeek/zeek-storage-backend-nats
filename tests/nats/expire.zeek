# @TEST-DOC: Tests basic successful NATS operations

# @TEST-REQUIRES: have-nats-jetstream
# @TEST-PORT: NATS_PORT

# @TEST-EXEC: cat $FILES/test-server.conf | sed "s|%NATS_PORT%|${NATS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./simple-ops.conf
# @TEST-EXEC: btest-bg-run nats nats-server -c ../simple-ops.conf
# @TEST-EXEC: zeek -Cr $TRACES/django-cloud.pcap %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0
# @TEST-EXEC: btest-diff out

@load base/frameworks/storage
@load Storage/Nats

redef Storage::expire_interval = 2secs;
redef exit_only_after_terminate = T;

type str: string;
global b: opaque of Storage::BackendHandle;

event check_removed()
	{
	local get2 = Storage::get(b, "abcd", F);
	print "get2 (FAIL)", get2;
	Storage::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Nats::NatsOptions;
	opts$bucket = "abucket";
	opts$create_kv = T;
	b = Storage::open_backend(Storage::NATS, opts, str, str);

	local put1 = Storage::put([ $backend=b, $key="abcd", $value="efgh",
	    $async_mode=F, $expire_time=2secs, $overwrite=T ]);
	print "put1", put1;

	local get1 = Storage::get(b, "abcd", F);
	print "get1", get1;

	schedule 5secs { check_removed() };
	}

event zeek_init()
	{
	schedule 100msecs { setup_test() };
	}
