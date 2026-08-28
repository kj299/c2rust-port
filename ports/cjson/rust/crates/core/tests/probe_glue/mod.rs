//! Probe glue — the bridge between the generated probe tests and the port.
//!
//! It is deliberately a ONE-LINE wrapper over `cjson_core::modes::run`, the same
//! function `crates/driver` runs. It used to re-implement the driver's mode
//! dispatch, which meant the generated tests and the differential could drift
//! apart and each still look green (LESSONS #21's residual). Fidelity lives in
//! one place now; keep this file trivial.

pub fn run_probe(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mode = *args.first().expect("probe args carry the driver mode");
    cjson_core::modes::run(mode, stdin)
}
