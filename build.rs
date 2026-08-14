fn main() {
    let out = "src/xdp_firewall.skel.rs";

    libbpf_cargo::SkeletonBuilder::new()
        .source("bpf/xdp_firewall.bpf.c")
        .build_and_generate(out)
        .unwrap();

    println!("cargo:rerun-if-changed=bpf/xdp_firewall.bpf.c");
}
