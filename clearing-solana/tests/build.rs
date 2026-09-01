use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest_dir.parent().unwrap();
    let program = workspace.join("program");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let sbf_target = out_dir.join("sbf-target");
    let sbf_out = out_dir.join("deploy");

    println!("cargo:rerun-if-changed={}", program.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        program.join("Cargo.toml").display()
    );

    let status = Command::new("cargo-build-sbf")
        .arg("--manifest-path")
        .arg(program.join("Cargo.toml"))
        .arg("--features")
        .arg("bpf-entrypoint")
        .arg("--sbf-out-dir")
        .arg(&sbf_out)
        .env("CARGO_TARGET_DIR", &sbf_target)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO")
        .env_remove("CLIPPY_ARGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to spawn cargo-build-sbf");
    assert!(status.success(), "cargo-build-sbf failed");

    println!("cargo:rustc-env=SBF_OUT_DIR={}", sbf_out.display());
}
