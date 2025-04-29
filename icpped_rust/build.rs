fn main() {
    println!("cargo:rustc-link-lib=dylib=userenv");
    println!("cargo:rustc-link-lib=dylib=ntdll");
}