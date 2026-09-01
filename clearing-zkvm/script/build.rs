use sp1_build::{BuildArgs, build_program_with_args};

fn main() {
    // Propagate the `poseidon2` feature to the guest build so the guest's hasher
    // matches the host's.
    let mut args = BuildArgs::default();
    if cfg!(feature = "poseidon2") {
        args.features = vec!["poseidon2".to_string()];
    }
    build_program_with_args("../program", args);
}
