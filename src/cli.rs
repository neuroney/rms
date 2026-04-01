//! Command-line entrypoint and dispatch.

use crate::{circom, dense_poly, greater_than, matrix_mul, page_rank, random_linear, random_mul};
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
    let Some(command) = args.first() else {
        matrix_mul::run();
        return Ok(());
    };

    let rest = &args[1..];
    match command.as_str() {
        "matrix" | "matrix_mul" | "matmul" => matrix_mul::run_with_args(rest),
        "greater" | "gt" | "greater_than" | "greaterthan" => greater_than::run_with_args(rest),
        "pagerank" | "page_rank" | "page-rank" => page_rank::run_with_args(rest),
        "random_mul" | "mul" => random_mul::run_with_args(rest),
        "random_linear" | "linear" => random_linear::run_with_args(rest),
        "dense_poly" | "poly" | "poly_dense" => dense_poly::run_with_args(rest),
        "circom" | "circom_json" | "circom_r1cs" | "import" => circom::run_with_args(rest),
        "--help" | "-h" | "help" => {
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
  cargo run -- matrix_mul [dim]
  cargo run -- matrix_mul [rows shared cols]
  cargo run -- greater_than [bit]
  cargo run -- page_rank [iterations]
  cargo run -- random_mul [num_inputs num_constraints]
  cargo run -- random_linear [num_inputs num_constraints]
  cargo run -- dense_poly [num_vars degree]
  cargo run -- import <constraints.json|circuit.r1cs|circuit.circom>
  cargo run -- circom <constraints.json|circuit.r1cs|circuit.circom>

说明:
  默认运行矩阵乘法示例。
  内置 7 个核心命令: circom、greater_than、matrix_mul、page_rank、random_mul、random_linear、dense_poly。
  前 6 个走 Rust 代码路径生成最终 RMS 工件；`circom` 负责从通用 Circom 电路导入并转换为 RMS。
  `matrix_mul` 支持 1 个方阵维度参数或 3 个矩阵维度参数，`page_rank` 支持迭代次数参数，其余命令支持对应的核心规模参数。"
}
