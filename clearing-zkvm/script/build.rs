use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    println!("cargo:rerun-if-env-changed=CLEARING_TREE_DEPTH");
    // Nested guest cargo may not load the workspace `.cargo/config.toml`.
    if std::env::var_os("CLEARING_TREE_DEPTH").is_none() {
        std::env::set_var("CLEARING_TREE_DEPTH", "8");
    }
    let mut args = BuildArgs::default();
    if cfg!(feature = "poseidon2") {
        args.features.push("poseidon2".to_string());
    }
    build_program_with_args("../program", args);
}
