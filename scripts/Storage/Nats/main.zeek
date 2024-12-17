module Nats;

export {
	## Options record for the NATS Storage backend
	type NatsOptions: record {
		## Path to the database's URL
		url: string &default="nats://localhost:4222";
		## The bucket to use for key-value operations
		bucket: string;
	};
}
