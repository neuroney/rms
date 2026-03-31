use zkbench::export::OutputFormat;

fn main() {
    let out_dir = zkbench::generators::default_fixture_out_dir();
    let format = std::env::args()
        .nth(1)
        .map(|raw| OutputFormat::parse(&raw))
        .transpose()
        .unwrap_or_else(|err| {
            eprintln!("error: {err}");
            std::process::exit(2);
        })
        .unwrap_or(OutputFormat::Bin);

    if let Err(err) = zkbench::generators::linear::generate_default_batch_suite(&out_dir, format) {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
