
use prost_build;

fn main() {
    // TODO: https://docs.rs/prost-build/latest/prost_build/#compiling-protoc-from-source
    std::env::set_var("PROTOC", "./src/res/protoc");
    // generate rust file from the protocol buffer
    prost_build::compile_protos(&["src/res/BEP.proto"], &["src/"]).unwrap();
}
