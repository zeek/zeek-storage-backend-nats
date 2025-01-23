module Nats;

export {
	## Options record for the NATS Storage backend
	type NatsOptions: record {
		## Path to the database's URL
		url: string &default="nats://localhost:4222";
		## Whether this is "strict" mode or not. Strict mode will force keys to be strings
		## and disallow other characters, which allows keys to more closely resemble what
		## NATS users may expect for subject names.
		strict: bool &default=F;
		## Path to the credentials file
		creds: string &optional;
		## Amount of time (in milliseconds) to wait for Jetstream API requests
		wait: int &optional;
		## The bucket to use for key-value operations
		bucket: string;
        ## The prefix for expiration keys to differentiate from the key itself
		expiration_prefix: string &default="expire";
		## Whether this should create a new key-value store or use an existing one.
		## Note that the only key/value configuration available if not creating a new
		## store is the bucket.
		create_kv: bool &default=F;
		## The max size of the bucket
		bucket_max_size: count &optional;
		## The max size of a value within the bucket
		value_max_size: count &optional;
		## TODO: Probably necessary to move this in to the framework's expiration
		ttl: count &optional;
	};
}
