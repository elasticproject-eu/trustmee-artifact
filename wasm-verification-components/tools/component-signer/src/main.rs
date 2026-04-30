use anyhow::{bail, Context, Result};
use chrono::DateTime;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::{
    borrow::Cow,
    fs,
    ops::Range,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};
use wasm_encoder::Encode;
use wasmparser::{Chunk, Parser as WasmParser, Payload};
use wasmsign2::{KeyPair, Module, PublicKey, SecretKey};

const COMPONENT_SIGNATURE_METADATA_SECTION_NAME: &str = "trustmee.component-signature-metadata";

#[derive(Parser, Debug)]
#[command(name = "trustmee-component-signer")]
#[command(about = "Add TrustMee signature expiry metadata and sign a Wasm verifier component")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a wasmsign2 key pair.
    GenerateKey(GenerateKeyArgs),
    /// Add expiry metadata and sign a Wasm verifier component.
    Sign(SignArgs),
}

#[derive(Args, Debug)]
struct GenerateKeyArgs {
    /// Output path for the PEM-encoded private key.
    #[arg(long)]
    private_key_out: PathBuf,

    /// Output path for the PEM-encoded public key.
    #[arg(long)]
    public_key_out: PathBuf,
}

#[derive(Args, Debug)]
struct SignArgs {
    /// Path to the unsigned Wasm component or module.
    #[arg(long)]
    component: PathBuf,

    /// Output path for the signed Wasm component or module.
    #[arg(long)]
    signed_component: PathBuf,

    /// RFC3339 timestamp embedded into the signed component as TrustMee expiry metadata.
    #[arg(long)]
    signature_expires_at: String,

    /// Generate a new key pair before signing instead of reading existing keys.
    #[arg(long)]
    generate_key: bool,

    /// PEM, DER, raw wasmsign2, or OpenSSH private key input path.
    #[arg(long)]
    private_key: Option<PathBuf>,

    /// PEM, DER, raw wasmsign2, or OpenSSH public key input path.
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// Output path for the generated PEM-encoded private key.
    #[arg(long)]
    private_key_out: Option<PathBuf>,

    /// Output path for the generated PEM-encoded public key.
    #[arg(long)]
    public_key_out: Option<PathBuf>,

    /// Optional TrustMee component trust store JSON output path for the signing key.
    #[arg(long)]
    trust_store_out: Option<PathBuf>,

    /// Fuel limit written into the optional trust store.
    #[arg(long, allow_hyphen_values = true, default_value_t = -1)]
    fuel: i64,

    /// Allow outbound network access for this signer in the optional trust store.
    #[arg(long, default_value_t = false)]
    allow_network: bool,

    /// RFC3339 trust-store valid_until timestamp. Defaults to --signature-expires-at.
    #[arg(long)]
    valid_until: Option<String>,
}

#[derive(Serialize)]
struct ComponentSignatureMetadata<'a> {
    expires_at: &'a str,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateKey(args) => run_generate_key(&args),
        Command::Sign(args) => run_sign(&args),
    }
}

fn run_generate_key(args: &GenerateKeyArgs) -> Result<()> {
    let key_pair = KeyPair::generate();
    let public_key = key_pair.pk.attach_default_key_id();

    write_file(&args.private_key_out, key_pair.sk.to_pem().as_bytes())?;
    write_file(&args.public_key_out, public_key.to_pem().as_bytes())?;

    println!("private_key={}", args.private_key_out.display());
    println!("public_key={}", args.public_key_out.display());
    Ok(())
}

fn run_sign(args: &SignArgs) -> Result<()> {
    validate_rfc3339_for_trustmee(&args.signature_expires_at)
        .context("parse --signature-expires-at")?;

    let valid_until = args
        .valid_until
        .as_deref()
        .unwrap_or(args.signature_expires_at.as_str());
    validate_rfc3339_for_trustmee(valid_until).context("parse --valid-until")?;

    let (secret_key, public_key) = load_or_generate_keys(args)?;
    let component_bytes =
        fs::read(&args.component).with_context(|| format!("read {}", args.component.display()))?;
    let component_bytes =
        component_bytes_with_expiry_metadata(&component_bytes, &args.signature_expires_at)?;
    let module =
        Module::deserialize(&mut &component_bytes[..]).context("deserialize component bytes")?;
    let signed_module = secret_key
        .sign(module, public_key.key_id())
        .context("sign component bytes with wasmsign2")?;

    let mut signed_bytes = Vec::new();
    signed_module
        .serialize(&mut signed_bytes)
        .context("serialize signed component")?;
    public_key
        .verify(&mut &signed_bytes[..], None)
        .context("verify signed component with public key")?;
    write_file(&args.signed_component, &signed_bytes)?;

    if let Some(trust_store_out) = &args.trust_store_out {
        write_trust_store(
            trust_store_out,
            &public_key,
            args.fuel,
            args.allow_network,
            valid_until,
        )?;
        println!("trust_store={}", trust_store_out.display());
    }

    println!("signed_component={}", args.signed_component.display());
    Ok(())
}

fn load_or_generate_keys(args: &SignArgs) -> Result<(SecretKey, PublicKey)> {
    if args.generate_key {
        if args.private_key.is_some() || args.public_key.is_some() {
            bail!("--generate-key cannot be combined with --private-key or --public-key");
        }

        let private_key_out = args
            .private_key_out
            .as_ref()
            .context("--generate-key requires --private-key-out")?;
        let public_key_out = args
            .public_key_out
            .as_ref()
            .context("--generate-key requires --public-key-out")?;
        let key_pair = KeyPair::generate();
        let public_key = key_pair.pk.clone().attach_default_key_id();

        write_file(private_key_out, key_pair.sk.to_pem().as_bytes())?;
        write_file(public_key_out, public_key.to_pem().as_bytes())?;
        println!("private_key={}", private_key_out.display());
        println!("public_key={}", public_key_out.display());
        return Ok((key_pair.sk, public_key));
    }

    if args.private_key_out.is_some() || args.public_key_out.is_some() {
        bail!("--private-key-out and --public-key-out are only valid with --generate-key");
    }

    let private_key = args
        .private_key
        .as_ref()
        .context("--private-key is required unless --generate-key is used")?;
    let public_key = args
        .public_key
        .as_ref()
        .context("--public-key is required unless --generate-key is used")?;
    let secret_key = SecretKey::from_any_file(private_key)
        .with_context(|| format!("read private key from {}", private_key.display()))?;
    let public_key = PublicKey::from_any_file(public_key)
        .with_context(|| format!("read public key from {}", public_key.display()))?
        .attach_default_key_id();

    Ok((secret_key, public_key))
}

fn validate_rfc3339_for_trustmee(raw_timestamp: &str) -> Result<()> {
    let nanos = DateTime::parse_from_rfc3339(raw_timestamp)
        .context("expected RFC3339 timestamp")?
        .timestamp_nanos_opt()
        .context("RFC3339 timestamp is out of range")?;

    if nanos < 0 {
        bail!("timestamp must not be earlier than the Unix epoch");
    }

    let _ = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    Ok(())
}

fn component_bytes_with_expiry_metadata(
    component_bytes: &[u8],
    expires_at: &str,
) -> Result<Vec<u8>> {
    if component_bytes.len() < 8 {
        bail!("component is shorter than the WebAssembly binary header");
    }

    let component_bytes = strip_existing_expiry_metadata(component_bytes)?;
    let metadata_payload = serde_json::to_vec(&ComponentSignatureMetadata { expires_at })
        .context("serialize signature expiry metadata")?;
    let metadata_section = wasm_encoder::CustomSection {
        name: Cow::Borrowed(COMPONENT_SIGNATURE_METADATA_SECTION_NAME),
        data: Cow::Borrowed(&metadata_payload),
    };
    let mut metadata_section_bytes = vec![0];
    metadata_section.encode(&mut metadata_section_bytes);

    let mut output = Vec::with_capacity(component_bytes.len() + metadata_section_bytes.len());
    output.extend_from_slice(&component_bytes[..8]);
    output.extend_from_slice(&metadata_section_bytes);
    output.extend_from_slice(&component_bytes[8..]);
    Ok(output)
}

fn strip_existing_expiry_metadata(component_bytes: &[u8]) -> Result<Vec<u8>> {
    let metadata_sections = component_signature_metadata_sections(component_bytes)?;
    if metadata_sections.is_empty() {
        return Ok(component_bytes.to_vec());
    }

    let mut stripped = Vec::with_capacity(component_bytes.len());
    let mut last = 0;
    for range in metadata_sections {
        stripped.extend_from_slice(&component_bytes[last..range.start]);
        last = range.end;
    }
    stripped.extend_from_slice(&component_bytes[last..]);
    Ok(stripped)
}

fn component_signature_metadata_sections(component_bytes: &[u8]) -> Result<Vec<Range<usize>>> {
    let mut metadata_sections = Vec::new();
    let mut parser = WasmParser::new(0);
    let mut input = component_bytes;
    let mut input_offset = 0;

    loop {
        let chunk = parser
            .parse(input, true)
            .context("parse verifier component section")?;
        let Chunk::Parsed { payload, consumed } = chunk else {
            bail!("verifier component parser unexpectedly requested more data");
        };

        let section_start = input_offset;
        input_offset += consumed;
        input = &component_bytes[input_offset..];

        match payload {
            Payload::CustomSection(section)
                if section.name() == COMPONENT_SIGNATURE_METADATA_SECTION_NAME =>
            {
                metadata_sections.push(section_start..input_offset);
            }
            Payload::CodeSectionStart { size, .. } => {
                parser.skip_section();
                input_offset += size as usize;
                input = &component_bytes[input_offset..];
            }
            Payload::ModuleSection {
                unchecked_range, ..
            }
            | Payload::ComponentSection {
                unchecked_range, ..
            } => {
                input_offset = unchecked_range.end;
                input = &component_bytes[input_offset..];
            }
            Payload::End(_) => break,
            _ => {}
        }
    }

    Ok(metadata_sections)
}

fn write_trust_store(
    path: &Path,
    public_key: &PublicKey,
    fuel: i64,
    allow_network: bool,
    valid_until: &str,
) -> Result<()> {
    let trust_store = serde_json::json!({
        "signers": [
            {
                "public_key": public_key.to_pem(),
                "fuel": fuel,
                "allow_network": allow_network,
                "valid_until": valid_until,
            }
        ]
    });
    let contents = serde_json::to_vec_pretty(&trust_store).context("serialize trust store JSON")?;
    write_file(path, &contents)
}

fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
    }
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_metadata_is_inserted_after_wasm_header() {
        let component = b"\0asm\r\0\x01\0";
        let with_metadata = component_bytes_with_expiry_metadata(component, "2030-01-01T00:00:00Z")
            .expect("add metadata");

        assert_eq!(&with_metadata[..8], component);
        assert_eq!(
            component_signature_metadata_sections(&with_metadata)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn expiry_metadata_is_replaced() {
        let component = b"\0asm\r\0\x01\0";
        let first = component_bytes_with_expiry_metadata(component, "2030-01-01T00:00:00Z")
            .expect("add metadata");
        let second = component_bytes_with_expiry_metadata(&first, "2031-01-01T00:00:00Z")
            .expect("replace metadata");

        assert_eq!(
            component_signature_metadata_sections(&second)
                .unwrap()
                .len(),
            1
        );
    }
}
