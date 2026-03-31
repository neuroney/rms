use crate::evalr1cs::{execute_circuit, get_output, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_to_bin, export_r1cs_to_json, load_r1cs_from_bin, load_r1cs_from_json,
    terms_to_export_string,
};
use crate::r1cs::{generate_controlled_r1cs, rms_linear_name};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions};
use crate::utils::{coeff_to_string, print_constraints};

pub fn run() {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  实验一：小电路变换前后对比                      ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let small = generate_controlled_r1cs(5, 50, 8, 0.5);

    println!("【变换前】");
    print_constraints(&small);
    small.print_stats();

    let transformed = choudhuri_transform(&small);
    println!("\n【Choudhuri 变换后】");
    print_constraints(&transformed.r1cs);
    transformed.r1cs.print_stats();
    println!("  膨胀倍数:        {:.2}x", transformed.blowup_factor);
    println!("  剩余 w×w 约束数: {}", transformed.r1cs.count_ww_gates());

    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);
    println!("\n【CSE 之后】");
    print_constraints(&optimized);
    optimized.print_stats();
    println!("  消除重复约束:    {}", eliminated);
    println!(
        "  最终膨胀倍数:    {:.2}x",
        optimized.constraints.len() as f64 / small.constraints.len() as f64
    );

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  实验三：膨胀倍数 vs w×w 比例                    ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!(
        "{:<10} {:>8} {:>10} {:>10} {:>8} {:>10}",
        "ww_ratio", "orig", "transform", "normalize", "elim", "blowup"
    );
    println!("{:-<62}", "");

    for ratio in [0.0, 0.1, 0.25, 0.5, 0.75, 0.9_f64] {
        let size = 1000;
        let r1cs = generate_controlled_r1cs(50, 50000, size, ratio);
        let original = r1cs.constraints.len();

        let transformed = choudhuri_transform(&r1cs);
        let after_t = transformed.r1cs.constraints.len();

        let (opt, elim) = eliminate_common_subexpressions(&transformed.r1cs);
        let after_cse = opt.constraints.len();

        println!(
            "{:<12} {:>8} {:>10} {:>10} {:>8} {:>9.2}x",
            format!("{:.0}%", ratio * 100.0),
            original,
            after_t,
            after_cse,
            elim,
            after_cse as f64 / original as f64,
        );
    }

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  实验四：固定 25% w×w，增大电路规模              ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!(
        "{:<12} {:>10} {:>12} {:>10} {:>12}",
        "orig", "transform", "normalize", "elim", "blowup"
    );

    println!("{:-<58}", "");

    for &size in &[10, 100, 1000, 10000] {
        let r1cs = generate_controlled_r1cs(50, 500000, size, 0.8);
        let original = r1cs.constraints.len();
        let transformed = choudhuri_transform(&r1cs);
        let (opt, elim) = eliminate_common_subexpressions(&transformed.r1cs);
        let after_cse = opt.constraints.len();

        println!(
            "{:<12} {:>10} {:>12} {:>10} {:>11.2}x",
            original,
            transformed.transformed_constraints,
            after_cse,
            elim,
            after_cse as f64 / original as f64,
        );
    }

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  实验五：验证变换前后对同一输入产生相同输出       ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let r1cs = generate_controlled_r1cs(5, 100, 10, 0.5);

    println!("【原始电路】");
    print_constraints(&r1cs);

    let transformed = choudhuri_transform(&r1cs);
    println!("【变换后电路】");
    print_constraints(&transformed.r1cs);

    for (x1, x2, x3, x4) in [
        (2u64, 3u64, 4u64, 5u64),
        (5, 7, 8, 9),
        (1, 1, 2, 2),
        (10, 4, 6, 8),
    ] {
        let mut assign_orig = Assignment::new(vec![(1, x1), (2, x2), (3, x3), (4, x4)]);
        let _ = execute_circuit(&r1cs, &mut assign_orig).is_some();
        let valid_orig = verify_assignment(&r1cs, &assign_orig);
        let out_orig = get_output(&r1cs, &assign_orig);

        let mut assign_trans = Assignment::new(vec![(1, x1), (2, x2), (3, x3), (4, x4)]);
        let _ = execute_circuit(&transformed.r1cs, &mut assign_trans).is_some();
        let valid_trans = verify_assignment(&transformed.r1cs, &assign_trans);
        let out_trans = get_output(&transformed.r1cs, &assign_trans);

        let same = out_orig == out_trans;
        println!(
            "  x1={}, x2={}, x3={}, x4={} → 原始输出={}, 变换后输出={}, 一致={}  [约束满足: orig={}, trans={}]",
            x1,
            x2,
            x3,
            x4,
            format_output(out_orig.as_ref()),
            format_output(out_trans.as_ref()),
            same,
            valid_orig,
            valid_trans
        );
    }

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  实验六：导出 R1CS 并读取示例                    ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let export_name = rms_linear_name(
        transformed.r1cs.num_inputs,
        transformed.r1cs.constraints.len(),
    );
    let export_json_path = format!("target/{}.json", export_name);
    let export_bin_path = format!("target/{}.bin", export_name);

    export_r1cs_to_json(&transformed.r1cs, &export_json_path).expect("导出 JSON 失败");
    export_r1cs_to_bin(&transformed.r1cs, &export_bin_path).expect("导出 BIN 失败");

    let exported_json = load_r1cs_from_json(&export_json_path).expect("读取 JSON 导出文件失败");
    let exported_bin = load_r1cs_from_bin(&export_bin_path).expect("读取 BIN 导出文件失败");

    println!("  已导出到: {}", export_json_path);
    println!("  已导出到: {}", export_bin_path);
    println!("  版本: {}", exported_json.version);
    println!("  约束数: {}", exported_json.constraints.len());
    println!("  执行顺序: 按 execution_order 依次计算");
    println!("  JSON/BIN 内容一致: {}", exported_json == exported_bin);
    println!("  前 3 条约束读取示例:");

    for constraint in exported_json.constraints.iter().take(3) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness,
        );
    }
}

fn format_output(value: Option<&ark_bn254::Fr>) -> String {
    value
        .map(coeff_to_string)
        .unwrap_or_else(|| "None".to_string())
}
