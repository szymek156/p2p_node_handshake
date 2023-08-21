# p2p_node_handshake
This code demonstrates connection establishment with the IPFS node. Uses multiselect protocol to agree on noise protocol. After that executes noise handshake.
# Compiling
The `protoc` compiler is required. To compile `.protobuf` message definitions. You can use your `protoc` installation by setting the `PROTOC` env variable while building. Otherwise default binary (linux-x86_64) from `/src/res` directory will be used.

# Running
## Start IPFS node:
On one terminal run ipfs node:
```
docker run --rm --name ipfs_host -v /tmp/ipfs_staging:/export -v /tmp/ipfs_data:/data/ipfs -p 4001:4001 -p 4001:4001/udp -p 127.0.0.1:8080:8080 -p 127.0.0.1:5001:5001 ipfs/kubo:latest
```
You should see following logs:
```
...
Swarm listening on /ip4/127.0.0.1/tcp/4001
...
Daemon is ready
```
After that IPFS node is up and running and ready to accept connections.
## Start initiator
Run `RUST_LOG=info cargo run` in the root of this repository to start a connection establishment process.

Successful run should be indicated by logs:
```
Connection established!
```

# Testing
Run `RUST_LOG=info cargo test`