//! Binary entrypoint delegating to the RMS CLI dispatcher.

fn main() -> std::process::ExitCode {
    rmsgen::cli::run()
}
