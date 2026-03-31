fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --example circom_json -- <constraints.json|circuit.r1cs>");
        std::process::exit(2);
    });

    zkbench::pipelines::circom_json::run(&path);
}
