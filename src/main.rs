//! Entry point of `winrig`: it parses the CLI and returns the exit code.
//!
//! All logic lives in [`winrig::app`]; this file only calls it and exits, so the
//! library tests cover the CLI paths, logging and both modes.

fn main() {
    std::process::exit(winrig::app::main());
}
