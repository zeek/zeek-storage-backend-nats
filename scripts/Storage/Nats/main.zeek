module Nats;

export {
	## Options record for the NATS Storage backend
	type NatsOptions: record {
		## Path to the database's URL
		url: string &default="nats://localhost:4222";
		## The bucket to use for key-value operations
		bucket: string;
		## The max size of the bucket
		bucket_max_size: count &optional;
		## The max size of a value within the bucket
		value_max_size: count &optional;
		## TODO: Probably necessary to move this in to the framework's expiration
		ttl: count &optional;
	};
}
