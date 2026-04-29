use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ciborium::from_reader;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sev::{
    firmware::{guest::AttestationReport, host::CertTableEntry},
    parser::ByteParser,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    hash::Hash,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Instant,
};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};
use tracing::{debug, warn};

use crate::trustee::verifier::snp_host_crypto_interface;

pub const SNP_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.snp-collateral+cbor";

#[derive(Serialize, Deserialize)]
pub struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

impl SnpEvidence {
    pub fn new(
        attestation_report: AttestationReport,
        cert_chain: Option<Vec<CertTableEntry>>,
    ) -> Self {
        Self {
            attestation_report,
            cert_chain,
        }
    }
}

#[derive(Deserialize)]
struct SnpCollateral {
    cert_chain: Vec<CertTableEntry>,
}

pub fn parse_evidence_bytes(evidence: &[u8]) -> Result<SnpEvidence> {
    if let Ok(s) = std::str::from_utf8(evidence) {
        if s.trim_start().starts_with('{') {
            let ev: SnpEvidence = serde_json::from_str(s).context("parse SNP evidence JSON")?;
            return Ok(ev);
        }
    }

    let report = AttestationReport::from_bytes(evidence).context("parse SNP report bytes")?;
    Ok(SnpEvidence::new(report, None))
}

pub fn parse_verifier_input(
    input: &crate::exports::trustee::verifier::verifier_interface::VerifierInput,
) -> Result<SnpEvidence> {
    let mut evidence = parse_evidence_bytes(&input.evidence).context("parse SNP evidence")?;
    let mut collateral = None;

    for endorsement in &input.endorsements {
        if endorsement.media_type != SNP_COLLATERAL_MEDIA_TYPE {
            continue;
        }

        let parsed: SnpCollateral =
            from_reader(endorsement.payload.as_slice()).with_context(|| {
                format!(
                    "parse SNP collateral endorsement `{}` as CBOR payload",
                    endorsement.label
                )
            })?;
        if collateral.replace(parsed.cert_chain).is_some() {
            bail!("multiple SNP collateral endorsements were provided");
        }
    }

    if let Some(cert_chain) = collateral {
        if evidence.cert_chain.is_some() {
            bail!("SNP evidence already contains `cert_chain`; refuse duplicate collateral");
        }
        evidence.cert_chain = Some(cert_chain);
    }

    Ok(evidence)
}

// KDS URL parameters
const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";

/// Attestation report versions supported
const REPORT_VERSION_MIN: u32 = 3;
const REPORT_VERSION_MAX: u32 = 5;

pub(crate) static CERT_CHAINS: LazyLock<HashMap<ProcessorGeneration, VendorCertificates>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        for proc in ProcessorGeneration::iter() {
            let certs = decode_vendor_certificates(match proc {
                ProcessorGeneration::Milan => include_bytes!("milan_ask_ark_asvk.pem"),
                ProcessorGeneration::Genoa => include_bytes!("genoa_ask_ark_asvk.pem"),
                ProcessorGeneration::Turin => include_bytes!("turin_ask_ark_asvk.pem"),
            })
            .unwrap();

            if certs.len() != 3 {
                panic!(
                    "Malformed cached Vendor Certs for {} processor (ASK, ARK, ASVK)",
                    proc
                );
            }

            let vendor_certs = VendorCertificates {
                ask_der: certs[0].clone(),
                ark_der: certs[1].clone(),
                asvk_der: certs[2].clone(),
            };

            map.insert(proc, vendor_certs);
        }

        map
    });

static PREOPEN_DIRS: LazyLock<Vec<String>> = LazyLock::new(|| {
    wasip2::filesystem::preopens::get_directories()
        .into_iter()
        .map(|(descriptor, path)| {
            // Keep returned descriptor handles alive for component lifetime.
            std::mem::forget(descriptor);
            path
        })
        .collect()
});

#[derive(Clone, Debug, Default)]
pub struct Snp;

impl Snp {
    pub fn new() -> Self {
        Self
    }

    fn cache_dir() -> Option<PathBuf> {
        for path in PREOPEN_DIRS.iter() {
            let candidate = PathBuf::from(path);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }

        PREOPEN_DIRS.first().map(PathBuf::from)
    }

    fn cache_path(cache_dir: &Path, vcek_url: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(vcek_url.as_bytes());
        let key = hex::encode(hasher.finalize());
        cache_dir.join("snp-vcek").join(format!("{key}.der"))
    }

    fn read_cache(cache_dir: &Path, vcek_url: &str) -> Option<Vec<u8>> {
        let path = Self::cache_path(cache_dir, vcek_url);
        std::fs::read(path).ok()
    }

    fn write_cache(cache_dir: &Path, vcek_url: &str, data: &[u8]) -> Result<()> {
        let path = Self::cache_path(cache_dir, vcek_url);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(&path, data).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Fetches the VCEK from the Key Distribution Service (KDS) using the provided attestation report.
    /// Returns the VCEK in DER format.
    fn fetch_vcek_from_kds(
        &self,
        att_report: &AttestationReport,
        proc_gen: &ProcessorGeneration,
    ) -> Result<Vec<u8>> {
        // Use attestation report to get data for URL.
        if att_report.chip_id.as_slice() == [0; 64] {
            bail!("Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0 to request VCEK from KDS.");
        }

        let hw_id = match proc_gen {
            ProcessorGeneration::Turin => {
                let shorter_bytes: &[u8] = &att_report.chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(att_report.chip_id),
        };

        // Request VCEK from KDS.
        let vcek_url: String = match proc_gen {
            ProcessorGeneration::Turin => {
                let Some(fmc) = att_report.reported_tcb.fmc else {
                    bail!("A Turin processor must have a fmc value");
                };

                format!(
                    "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                    {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    proc_gen,
                    fmc,
                    att_report.reported_tcb.bootloader,
                    att_report.reported_tcb.tee,
                    att_report.reported_tcb.snp,
                    att_report.reported_tcb.microcode
                )
            }
            _ => {
                format!(
                    "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                    {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    proc_gen,
                    att_report.reported_tcb.bootloader,
                    att_report.reported_tcb.tee,
                    att_report.reported_tcb.snp,
                    att_report.reported_tcb.microcode
                )
            }
        };

        // Paper-eval: SNP_VCEK_DISABLE_CACHE=1 forces a network fetch on
        // every call (eval 7).
        let vcek_cache_disabled = std::env::var("SNP_VCEK_DISABLE_CACHE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if !vcek_cache_disabled {
            if let Some(cache_dir) = Self::cache_dir() {
                if let Some(bytes) = Self::read_cache(&cache_dir, &vcek_url) {
                    debug!("VCEK cache: HIT {}", vcek_url);
                    return Ok(bytes);
                }
            }
        }

        let start = Instant::now();
        let resp = waki::Client::new()
            .get(&vcek_url)
            .send()
            .with_context(|| format!("Unable to send request for VCEK: {vcek_url}"))?;
        let status = resp.status_code();
        let body = resp.body().context("Unable to parse VCEK")?;

        debug!(
            "VCEK fetch: HTTP {} from {} ({:?})",
            status,
            vcek_url,
            start.elapsed()
        );

        if status != 200 {
            bail!("Unable to fetch VCEK from URL: HTTP {status}, {vcek_url}");
        }

        if !vcek_cache_disabled {
            if let Some(cache_dir) = Self::cache_dir() {
                if let Err(err) = Self::write_cache(&cache_dir, &vcek_url, &body) {
                    warn!("VCEK cache: write failed for {}: {}", vcek_url, err);
                } else {
                    debug!("VCEK cache: stored {}", vcek_url);
                }
            }
        }

        Ok(body)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VendorCertificates {
    pub(crate) ask_der: Vec<u8>,
    pub(crate) ark_der: Vec<u8>,
    pub(crate) asvk_der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString, Display, EnumIter, Hash)]
#[strum(serialize_all = "PascalCase", ascii_case_insensitive)]
pub(crate) enum ProcessorGeneration {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 5th Gen AMD EPYC Processor (Standard)
    Turin,
}

pub fn evaluate(
    snp: &Snp,
    evidence: SnpEvidence,
    expected_report_data: Option<&[u8]>,
    expected_init_data_hash: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let evaluate_start = std::time::Instant::now();
    let SnpEvidence {
        attestation_report: report,
        cert_chain,
    } = evidence;

    // See Trustee Issue#589 https://github.com/confidential-containers/trustee/issues/589
    // Version 3 minimum is needed to tell processor type in report.
    if report.version < REPORT_VERSION_MIN {
        bail!("Attestation Report version is too old. Please update your firmware.");
    } else if report.version > REPORT_VERSION_MAX {
        bail!("Unexpected attestation report version. Check SNP Firmware ABI specification");
    }

    // Get the processor model from the report.
    let proc_gen: ProcessorGeneration = get_processor_generation(&report)?;

    // Get vendor certs for specific processor type.
    let vendor_certs = CERT_CHAINS
        .get(&proc_gen)
        .ok_or_else(|| anyhow!("Vendor certs not found for processor type: {proc_gen:?}"))?;

    // Paper-eval: start of cert-chain (host-crypto delegated) phase.
    let cert_chain_start = std::time::Instant::now();

    let fetched_vcek_der = match cert_chain {
        Some(_) => snp_host_crypto_interface::OptionalBytes::NotProvided,
        None => {
            let vcek_buf = snp
                .fetch_vcek_from_kds(&report, &proc_gen)
                .context("Failed to fetch VCEK from KDS")?;
            snp_host_crypto_interface::OptionalBytes::Value(vcek_buf)
        }
    };

    let host_evidence = SnpEvidence::new(report.clone(), cert_chain.clone());
    let host_evidence_bytes =
        serde_json::to_vec(&host_evidence).context("serialize evidence for host crypto import")?;

    // Paper-eval: signature phase encompasses the host-crypto call (which
    // verifies chain + signature together).
    let signature_start = std::time::Instant::now();
    let verified_vek_meta = snp_host_crypto_interface::verify_snp_crypto(
        &host_evidence_bytes,
        to_host_processor_generation(&proc_gen),
        &vendor_certs.ark_der,
        &vendor_certs.ask_der,
        &vendor_certs.asvk_der,
        &fetched_vcek_der,
    )
    .map_err(|e| anyhow!(e))
    .context("host SNP crypto verification failed")?;

    compare_verified_vek_meta_to_report(&report, &proc_gen, &verified_vek_meta)
        .context("Reported TCB values do not match")?;
    let signature_end = std::time::Instant::now();

    if report.vmpl != 0 {
        bail!("VMPL Check Failed");
    }

    // Verify expected data.
    if let Some(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "SNP");

        if expected_report_data != report.report_data.to_vec() {
            warn!(
                "Report data mismatch. Given: {}, Expected: {}",
                hex::encode(report.report_data),
                hex::encode(expected_report_data)
            );
            bail!("Report Data Mismatch");
        }
    };

    if let Some(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of HOST_DATA.");
        let expected_init_data_hash =
            regularize_data(expected_init_data_hash, 32, "HOST_DATA", "SNP");
        if expected_init_data_hash != report.host_data.to_vec() {
            bail!("Host Data Mismatch");
        }
    }

    let claims = parse_tee_evidence(&report);
    if timing_enabled() {
        let cert_chain_ms = signature_start
            .saturating_duration_since(cert_chain_start)
            .as_secs_f64()
            * 1000.0;
        let signature_ms = signature_end
            .saturating_duration_since(signature_start)
            .as_secs_f64()
            * 1000.0;
        let end = std::time::Instant::now();
        let pre_ms = cert_chain_start
            .saturating_duration_since(evaluate_start)
            .as_secs_f64()
            * 1000.0;
        let post_ms = end.saturating_duration_since(signature_end).as_secs_f64() * 1000.0;
        let others_ms = pre_ms + post_ms;
        emit_snp_step_timing(cert_chain_ms, signature_ms, others_ms);
    }
    Ok(claims)
}

/// Paper-eval gate for step-timing emission to stderr.
fn timing_enabled() -> bool {
    std::env::var("WVC_EMIT_TIMING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn emit_snp_step_timing(cert_chain_ms: f64, signature_ms: f64, others_ms: f64) {
    let mode = std::env::var("SNP_TIMING_MODE").unwrap_or_else(|_| "wasm".to_string());
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "snp_step_timing",
            "mode": mode,
            "cert_chain_ms": cert_chain_ms,
            "signature_ms": signature_ms,
            "others_ms": others_ms,
            "total_ms": cert_chain_ms + signature_ms + others_ms,
        })
    );
}

fn to_host_processor_generation(
    proc_gen: &ProcessorGeneration,
) -> snp_host_crypto_interface::ProcessorGeneration {
    match proc_gen {
        ProcessorGeneration::Milan => snp_host_crypto_interface::ProcessorGeneration::Milan,
        ProcessorGeneration::Genoa => snp_host_crypto_interface::ProcessorGeneration::Genoa,
        ProcessorGeneration::Turin => snp_host_crypto_interface::ProcessorGeneration::Turin,
    }
}

fn compare_verified_vek_meta_to_report(
    report: &AttestationReport,
    proc_gen: &ProcessorGeneration,
    meta: &snp_host_crypto_interface::VerifiedVekMeta,
) -> Result<()> {
    if meta.vek_kind == snp_host_crypto_interface::VekKind::Vcek {
        let hw_id = match &meta.hw_id {
            snp_host_crypto_interface::OptionalBytes::Value(bytes) => bytes,
            snp_host_crypto_interface::OptionalBytes::NotProvided => {
                bail!("Host crypto interface did not return HW_ID for VCEK")
            }
        };

        if hw_id.as_slice() != report.chip_id {
            bail!("Chip ID mismatch");
        }
    }

    if meta.microcode_spl != report.reported_tcb.microcode {
        bail!("Microcode version mismatch");
    }

    if meta.snp_spl != report.reported_tcb.snp {
        bail!("SNP version mismatch");
    }

    if meta.tee_spl != report.reported_tcb.tee {
        bail!("TEE version mismatch");
    }

    if meta.bootloader_spl != report.reported_tcb.bootloader {
        bail!("Boot loader version mismatch");
    }

    if *proc_gen == ProcessorGeneration::Turin {
        let Some(report_fmc) = report.reported_tcb.fmc else {
            bail!("A Turin processor must have a fmc value");
        };
        if meta.fmc_spl != Some(report_fmc) {
            bail!("FMC version mismatch");
        }
    }

    Ok(())
}

/// Parses the attestation report and extracts the TEE evidence claims.
/// Returns a JSON-formatted map of parsed claims.
pub(crate) fn parse_tee_evidence(report: &AttestationReport) -> serde_json::Value {
    json!({
        "tee_type": "snp",

        // policy fields
        "policy_abi_major": report.policy.abi_major(),
        "policy_abi_minor": report.policy.abi_minor(),
        "policy_smt_allowed": report.policy.smt_allowed(),
        "policy_migrate_ma": report.policy.migrate_ma_allowed(),
        "policy_debug_allowed": report.policy.debug_allowed(),
        "policy_single_socket": report.policy.single_socket_required(),

        // versioning info
        "reported_tcb_bootloader": report.reported_tcb.bootloader,
        "reported_tcb_tee": report.reported_tcb.tee,
        "reported_tcb_snp": report.reported_tcb.snp,
        "reported_tcb_microcode": report.reported_tcb.microcode,

        // platform info
        "platform_tsme_enabled": report.plat_info.tsme_enabled(),
        "platform_smt_enabled": report.plat_info.smt_enabled(),

        // measurements
        "measurement": hex::encode(report.measurement),
        "report_data": hex::encode(report.report_data),
        "init_data": hex::encode(report.host_data),
    })
}

/// Determines the processor model based on the family and model IDs from the attestation report.
fn get_processor_generation(att_report: &AttestationReport) -> Result<ProcessorGeneration> {
    let cpu_fam = att_report
        .cpuid_fam_id
        .ok_or_else(|| anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_mod = att_report
        .cpuid_mod_id
        .ok_or_else(|| anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcessorGeneration::Milan),
            0x10..=0x1F | 0xA0..0xAF => Ok(ProcessorGeneration::Genoa),
            _ => Err(anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcessorGeneration::Turin),

            _ => Err(anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow!("Processor family not supported")),
    }
}

/// Padding or truncate the given data slice to the given `len` bytes.
fn regularize_data(data: &[u8], len: usize, data_name: &str, arch: &str) -> Vec<u8> {
    use std::cmp::Ordering;

    let data_len = data.len();
    match data_len.cmp(&len) {
        Ordering::Less => {
            debug!(
                "The input {data_name} of {arch} is shorter than {len} bytes, will be padded with '\\0'."
            );
            let mut data = data.to_vec();
            data.resize(len, b'\0');
            data
        }
        Ordering::Equal => data.to_vec(),
        Ordering::Greater => {
            debug!(
                "The input {data_name} of {arch} is longer than {len} bytes, will be truncated to {len} bytes."
            );
            data[..len].to_vec()
        }
    }
}

fn decode_vendor_certificates(pem_bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pem_text = std::str::from_utf8(pem_bytes).context("vendor certificate PEM is not UTF-8")?;
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut remaining = pem_text;

    while let Some(begin) = remaining.find(begin_marker) {
        let after_begin = &remaining[begin + begin_marker.len()..];
        let end = after_begin
            .find(end_marker)
            .ok_or_else(|| anyhow!("unterminated certificate PEM block"))?;
        let body = &after_begin[..end];
        let b64 = body.lines().map(str::trim).collect::<String>();
        certs.push(
            STANDARD
                .decode(b64.as_bytes())
                .context("decode vendor certificate PEM block")?,
        );
        remaining = &after_begin[end + end_marker.len()..];
    }

    if certs.is_empty() {
        bail!("no certificate PEM blocks found");
    }

    Ok(certs)
}
