use zkbench::export::OutputFormat;

fn main() {
    let out_dir = zkbench::generators::default_fixture_out_dir();

    if let Err(err) =
        zkbench::generators::mul::generate_default_batch_suite(&out_dir, OutputFormat::Bin)
    {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
