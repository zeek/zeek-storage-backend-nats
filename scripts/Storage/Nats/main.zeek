module Nats;

export {
	## Options record for the NATS Storage backend
	type NatsOptions: record {
		## Path to the database's URL
		url: string &default="nats://localhost:4222";
		## Path to the credentials file
		creds: string &optional;
		## Path to the credentials file
		## The prefix for the Jetstream
		jetstream_prefix: string &optional;
		## The domain for the Jetstream. Cannot be set if prefix is.
		domain_prefix: string &optional;
		## Amount of time (in milliseconds) to wait for Jetstream API requests
		wait: int &optional;
		## The bucket to use for key-value operations
		bucket: string;
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
