fn main() {
    std::env::set_var("PROTOC", "./src/res/protoc");
    // generate rust file from the protocol buffer
    prost_build::compile_protos(&["src/res/ipfs_noise_payloads.proto"], &["src/"]).unwrap();
}
