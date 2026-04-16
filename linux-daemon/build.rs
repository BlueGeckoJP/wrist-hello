use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-link-search=native=../common");
    println!("cargo:rustc-link-lib=static=common");

    let bindings = bindgen::Builder::default()
        .header("../common/common.h")
        .allowlist_file(".*/common/common\\.h$")
        .clang_arg("-fparse-all-comments")
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
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
