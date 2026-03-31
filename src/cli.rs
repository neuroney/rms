//! Command-line entrypoint and dispatch.

use crate::pipelines;
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
            pipelines::matrix_mul::run();
            Ok(())
        }
        [arg] if matches!(arg.as_str(), "matrix" | "matrix_mul" | "matmul") => {
            pipelines::matrix_mul::run();
            Ok(())
        }
        [arg]
            if matches!(
                arg.as_str(),
                "greater" | "gt" | "greater_than" | "greaterthan"
            ) =>
        {
            pipelines::greater_than::run();
            Ok(())
        }
        [cmd, path] if matches!(cmd.as_str(), "circom" | "circom_json" | "circom_r1cs") => {
            pipelines::circom_json::run(path);
            Ok(())
        }
        [arg]
            if matches!(
                arg.as_str(),
                "--random" | "random" | "--random_rms" | "random_rms"
            ) =>
        {
            pipelines::random_rms::run();
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
  cargo run --example matrix_mul
  cargo run --example greater_than
  cargo run --example random_rms
  cargo run --example circom_json -- <constraints.json|circuit.r1cs>
  cargo run --bin gen_rms_linear [json|bin]
  cargo run --bin gen_rms_mul
  cargo run --bin gen_rms_poly [json|bin]
  cargo run --bin gen_rms_poly_full [json|bin]

说明:
  默认运行矩阵乘法示例。
  `greater_than` 运行手工构造的整数比较电路示例。
  `circom` 导入 Circom JSON 或二进制 R1CS 工件并执行 RMS 变换。
  Cargo 示例放在仓库根 `examples/`，生成器工具放在 `src/bin/`。
  `gen_rms_poly_full` 支持通过环境变量覆盖参数:
    RMS_POLY_FULL_OUT_DIR
    RMS_POLY_FULL_NUM_VARS
    RMS_POLY_FULL_MIN_DEGREE
    RMS_POLY_FULL_MAX_DEGREE
    RMS_POLY_FULL_SEED"
}
