use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=dylib=userenv");
    println!("cargo:rustc-link-lib=dylib=ntdll");
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("ICED_WRAPPER_H")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("iced_wrapper.h"));

    let crate_dir = env::var("OUT_DIR").unwrap();
    let out_path = format!("{}/iced_wrapper.h", crate_dir);

    println!("cargo:warning=Generating header at: {}", out_path);
}

