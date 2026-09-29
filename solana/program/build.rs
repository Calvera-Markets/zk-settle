fn main() {
    println!("cargo:rerun-if-env-changed=CLEARING_TREE_DEPTH");
    let raw = std::env::var("CLEARING_TREE_DEPTH").unwrap_or_else(|_| "128".into());
    let depth: u8 = raw
        .parse()
        .unwrap_or_else(|_| panic!("CLEARING_TREE_DEPTH must be an integer 1..=128, got {raw:?}"));
    assert!(
        (1..=128).contains(&depth),
        "CLEARING_TREE_DEPTH must be 1..=128, got {depth}"
    );
    println!("cargo:rustc-env=CLEARING_TREE_DEPTH={depth}");
}
