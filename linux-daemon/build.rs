use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-link-search=native=../common");
    println!("cargo:rustc-link-lib=static=common");

    let header_path = PathBuf::from("../common/common.h");

    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .clang_arg("-fparse-all-comments")
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("SocketPayload")
        .allowlist_type("ElapsedStatus")
        .allowlist_function("socket_payload_deserialize")
        .allowlist_function("socket_payload_serialize")
        .prepend_enum_name(false)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=../common/common.h");
    println!("cargo:rerun-if-changed=../common/common.c");
    println!("cargo:rerun-if-changed=../common/libcommon.a");
}
