use std::env;
use std::fs;

use anyhow::{anyhow, Context, Result};

#[cfg(feature = "tdx-verifier")]
use verifier::intel_dcap::ecdsa_quote_verification;

fn usage() -> ! {
    eprintln!("usage: pcs_fetch [--qcnl-config PATH] <tdx-quote-path>");
    std::process::exit(2);
}

#[cfg(feature = "tdx-verifier")]
fn main() -> Result<()> {
    let mut quote_path: Option<String> = None;
    let mut qcnl_path: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--qcnl-config" => {
                let Some(path) = args.next() else {
                    usage();
                };
                qcnl_path = Some(path);
            }
            "-h" | "--help" => {
                eprintln!("usage: pcs_fetch [--qcnl-config PATH] <tdx-quote-path>");
                return Ok(());
            }
            _ => {
                if quote_path.is_some() {
                    usage();
                }
                quote_path = Some(arg);
            }
        }
    }

    let Some(quote_path) = quote_path else {
        usage();
    };

    if let Some(path) = &qcnl_path {
        env::set_var("QCNL_CONF_PATH", path);
        env::set_var("SGX_QCNL_CONFIG_FILE", path);
    }

    let quote = fs::read(&quote_path).with_context(|| format!("read {}", quote_path))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| anyhow!("failed to build tokio runtime: {err}"))?;
    let claims = runtime
        .block_on(ecdsa_quote_verification(&quote))
        .map_err(|err| anyhow!("quote verification failed: {err}"))?;
    println!("Claims: {:#?}", claims);

    println!("Quote verification ok.");
    Ok(())
}

#[cfg(not(feature = "tdx-verifier"))]
fn main() {
    eprintln!("pcs_fetch requires the `tdx-verifier` feature.");
    std::process::exit(2);
}
