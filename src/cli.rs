//! Command-line entrypoint and dispatch.

use crate::examples;
use std::process::ExitCode;

pub fn run() -> ExitCode {
    match dispatch(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [] => {
            examples::matrix_mul::run();
            Ok(())
        }
        [arg] if matches!(arg.as_str(), "matrix" | "matrix_mul" | "matmul") => {
            examples::matrix_mul::run();
            Ok(())
        }
        [arg]
            if matches!(
                arg.as_str(),
                "greater" | "gt" | "greater_than" | "greaterthan"
            ) =>
        {
            examples::greater_than::run();
            Ok(())
        }
        [cmd, path] if matches!(cmd.as_str(), "circom" | "circom_json" | "circom_r1cs") => {
            examples::circom_json::run(path);
            Ok(())
        }
        [arg]
            if matches!(
                arg.as_str(),
                "--random" | "random" | "--random_rms" | "random_rms"
            ) =>
        {
            examples::random_rms::run();
            Ok(())
        }
        [arg] if matches!(arg.as_str(), "--help" | "-h" | "help") => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("未知命令: {}\n\n{}", args.join(" "), usage_text())),
    }
}

fn print_usage() {
    println!("{}", usage_text());
}

fn usage_text() -> &'static str {
    "\
RMS Toolkit

用法:
  cargo run
  cargo run -- matrix_mul
  cargo run -- greater_than
  cargo run -- random
  cargo run -- circom <constraints.json|circuit.r1cs>

说明:
  默认运行矩阵乘法示例。
  `greater_than` 运行手工构造的整数比较电路示例。
  `circom` 导入 Circom JSON 或二进制 R1CS 工件并执行 RMS 变换。"
}
