//! Command-line entrypoint and dispatch.

use crate::{
    circom, db_select, dense_poly, fix_mat, greater_than, mimc7, page_rank, random_linear,
    random_mul, two_mat,
};
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
        two_mat::run();
        return Ok(());
    };

    let rest = &args[1..];
    match command.as_str() {
        "fixmat" | "fix_mat" | "fix-mat" => fix_mat::run_with_args(rest),
        "twomat" | "two_mat" | "two-mat" => two_mat::run_with_args(rest),
        "pubdb" | "pub_db" | "pub-db" => db_select::run_pub_with_args(rest),
        "privdb" | "priv_db" | "priv-db" => db_select::run_priv_with_args(rest),
        "greater" | "gt" | "greater_than" | "greaterthan" => greater_than::run_with_args(rest),
        "mimc7" | "mimc" => mimc7::run_with_args(rest),
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
  cargo run -- fixmat [dim]
  cargo run -- twomat [dim]
  cargo run -- pubdb [x]
  cargo run -- privdb [x]
  cargo run -- greater_than [bit]
  cargo run -- mimc7 [num_rounds]
  cargo run -- page_rank [iterations]
  cargo run -- page_rank [num_vertices iterations]
  cargo run -- random_mul [num_inputs num_constraints]
  cargo run -- random_linear [num_inputs num_constraints]
  cargo run -- dense_poly [num_vars degree]
  cargo run -- import <constraints.json|circuit.r1cs|circuit.circom>
  cargo run -- circom <constraints.json|circuit.r1cs|circuit.circom>

说明:
  默认运行 TwoMat 示例。
  内置 11 个核心命令: circom、dense_poly、fixmat、greater_than、mimc7、page_rank、privdb、pubdb、random_linear、random_mul、twomat。
  其中 10 个走 Rust 代码路径生成最终 RMS 工件；`circom` 负责从通用 Circom 电路导入并转换为 RMS。
  `fixmat` 接收公开固定矩阵与私有向量乘法的方阵维度，`twomat` 接收两个私有方阵乘法的维度。
  `page_rank` 支持 `iterations` 或 `num_vertices iterations`，`pubdb`/`privdb` 接收指数 `x` 并设置 `n=2^x`，其余命令支持对应的核心规模参数。"
}
