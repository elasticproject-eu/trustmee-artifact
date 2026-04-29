use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;
use wasmsign2::{KeyPair, Module};

#[derive(Parser, Debug)]
#[command(name = "generate-component-signature-assets")]
#[command(about = "Generate a sample keypair, trust store, and signed Wasm component")]
struct Args {
    /// Path to the unsigned Wasm component to sign
    #[arg(long)]
    component: PathBuf,

    /// Directory where generated assets will be written
    #[arg(long)]
    output_dir: PathBuf,

    /// Output filename for the PEM-encoded private key
    #[arg(long, default_value = "component.private.pem")]
    private_key_name: String,

    /// Output filename for the PEM-encoded public key
    #[arg(long, default_value = "component.public.pem")]
    public_key_name: String,

    /// Output filename for the trust store JSON
    #[arg(long, default_value = "component.trust-store.json")]
    trust_store_name: String,

    /// Output filename for the signed Wasm component
    #[arg(long, default_value = "component.signed.wasm")]
    signed_component_name: String,

    /// Fuel limit written into the trust store
    #[arg(long, allow_hyphen_values = true, default_value_t = -1)]
    fuel: i64,

    /// Allow outbound network access for this signer in the trust store
    #[arg(long, default_value_t = false)]
    allow_network: bool,

    /// RFC3339 timestamp used for the trust store's valid_until field
    #[arg(long, default_value = "2035-01-01T00:00:00Z")]
    valid_until: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("create {}", args.output_dir.display()))?;

    let key_pair = KeyPair::generate();
    let public_key = key_pair.pk.clone().attach_default_key_id();
    let key_id = public_key.key_id().cloned();

    let private_key_path = args.output_dir.join(&args.private_key_name);
    let public_key_path = args.output_dir.join(&args.public_key_name);
    let trust_store_path = args.output_dir.join(&args.trust_store_name);
    let signed_component_path = args.output_dir.join(&args.signed_component_name);

    std::fs::write(&private_key_path, key_pair.sk.to_pem())
        .with_context(|| format!("write {}", private_key_path.display()))?;
    std::fs::write(&public_key_path, public_key.to_pem())
        .with_context(|| format!("write {}", public_key_path.display()))?;

    let trust_store = json!({
        "signers": [
            {
                "public_key": public_key.to_pem(),
                "fuel": args.fuel,
                "allow_network": args.allow_network,
                "valid_until": args.valid_until,
            }
        ]
    });
    std::fs::write(
        &trust_store_path,
        serde_json::to_vec_pretty(&trust_store).context("serialize trust store JSON")?,
    )
    .with_context(|| format!("write {}", trust_store_path.display()))?;

    let component_bytes = std::fs::read(&args.component)
        .with_context(|| format!("read {}", args.component.display()))?;
    let module =
        Module::deserialize(&mut &component_bytes[..]).context("deserialize component bytes")?;
    let signed_module = key_pair
        .sk
        .sign(module, key_id.as_ref())
        .context("sign component bytes")?;
    let mut signed_bytes = Vec::new();
    signed_module
        .serialize(&mut signed_bytes)
        .context("serialize signed component")?;
    std::fs::write(&signed_component_path, signed_bytes)
        .with_context(|| format!("write {}", signed_component_path.display()))?;

    println!("private_key={}", private_key_path.display());
    println!("public_key={}", public_key_path.display());
    println!("trust_store={}", trust_store_path.display());
    println!("signed_component={}", signed_component_path.display());
    Ok(())
}
