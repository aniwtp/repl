fn main() {
    println!("cargo:rerun-if-changed=capnp/repl.capnp");
    capnpc::CompilerCommand::new()
        .src_prefix("capnp")
        .file("capnp/repl.capnp")
        .run()
        .expect("capnp schema compilation");
}
