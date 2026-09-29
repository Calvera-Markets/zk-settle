fn main() {
    println!("cargo:rerun-if-env-changed=CLEARING_TREE_DEPTH");
    let raw = std::env::var("CLEARING_TREE_DEPTH").unwrap_or_else(|_| "8".into());
    let depth: u8 = raw
        .parse()
        .unwrap_or_else(|_| panic!("CLEARING_TREE_DEPTH must be an integer 1..=16, got {raw:?}"));
    assert!(
        (1..=16).contains(&depth),
        "CLEARING_TREE_DEPTH for circuits must be 1..=16 (dense 2^DEPTH leaves), got {depth}"
    );
    println!("cargo:rustc-env=CLEARING_TREE_DEPTH={depth}");
}
