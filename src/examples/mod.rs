pub mod circom_json;
pub mod greater_than;
pub mod matrix_mul;
pub mod random_rms;

pub fn run_from_args() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.as_slice() {
        [] => matrix_mul::run(),
        [arg] if arg == "matrix" || arg == "matrix_mul" || arg == "matmul" => matrix_mul::run(),
        [arg]
            if arg == "greater" || arg == "gt" || arg == "greater_than" || arg == "greaterthan" =>
        {
            greater_than::run()
        }
        [cmd, path] if cmd == "circom" || cmd == "circom_json" || cmd == "circom_r1cs" => {
            circom_json::run(path)
        }
        [arg]
            if arg == "--random"
                || arg == "random"
                || arg == "--random_rms"
                || arg == "random_rms" =>
        {
            random_rms::run()
        }
        [arg] if arg == "--help" || arg == "-h" || arg == "help" => print_usage(),
        _ => {
            eprintln!("未知命令: {}", args.join(" "));
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("用法:");
    println!("  cargo run");
    println!("  cargo run -- matrix_mul");
    println!("  cargo run -- greater_than");
    println!("  cargo run -- circom <constraints.json|circuit.r1cs>");
    println!("  cargo run -- random");
}
