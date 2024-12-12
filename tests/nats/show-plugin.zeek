# @TEST-EXEC: zeek -NN Storage::Nats |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
