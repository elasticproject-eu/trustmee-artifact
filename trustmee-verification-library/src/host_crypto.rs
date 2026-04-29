use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{oid, FromDer, Integer, OctetString, Oid};
use openssl::{nid::Nid, x509};
use serde::{Deserialize, Serialize};
use sev::{
    certs::snp::{ca::Chain as CaChain, Certificate, Chain, Verifiable},
    firmware::{
        guest::AttestationReport,
        host::{CertTableEntry, CertType},
    },
    parser::ByteParser,
};
use x509_parser::prelude::*;

pub(crate) const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
pub(crate) const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
pub(crate) const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
pub(crate) const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
pub(crate) const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);
pub(crate) const FMC_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostVekKind {
    Vcek,
    Vlek,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostVerifiedVekMeta {
    pub vek_kind: HostVekKind,
    pub hw_id: Option<Vec<u8>>,
    pub bootloader_spl: u8,
    pub tee_spl: u8,
    pub snp_spl: u8,
    pub microcode_spl: u8,
    pub fmc_spl: Option<u8>,
}

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

#[derive(Clone, Debug)]
enum VendorEndorsementKey {
    Vcek,
    Vlek,
}

#[derive(Clone, Debug)]
struct VendorCertificates {
    ask: Certificate,
    ark: Certificate,
    asvk: Certificate,
}

pub fn verify_snp_crypto_host(
    evidence: &[u8],
    processor: HostProcessorGeneration,
    vendor_ark_der: &[u8],
    vendor_ask_der: &[u8],
    vendor_asvk_der: &[u8],
    fetched_vcek_der: Option<&[u8]>,
) -> Result<HostVerifiedVekMeta> {
    let evidence = parse_evidence_bytes(evidence).context("parse SNP evidence")?;
    let SnpEvidence {
        attestation_report: report,
        cert_chain,
    } = evidence;

    let expected_processor = map_processor_generation(processor);
    let actual_processor = get_processor_generation(&report)?;
    if actual_processor != expected_processor {
        bail!(
            "processor generation mismatch between caller and evidence: expected {:?}, got {:?}",
            expected_processor,
            actual_processor
        );
    }

    let vendor_certs = VendorCertificates {
        ask: Certificate::from_bytes(vendor_ask_der).context("parse vendor ASK")?,
        ark: Certificate::from_bytes(vendor_ark_der).context("parse vendor ARK")?,
        asvk: Certificate::from_bytes(vendor_asvk_der).context("parse vendor ASVK")?,
    };

    let vek = match cert_chain {
        Some(chain) => verify_supplied_cert_chain(chain, &vendor_certs)?,
        None => verify_fetched_vcek(
            fetched_vcek_der.ok_or_else(|| anyhow!("missing fetched VCEK bytes"))?,
            &vendor_certs,
        )?,
    };

    (&vek, &report)
        .verify()
        .context("Report signature verification against VEK signature failed")?;

    extract_verified_vek_meta(&vek, expected_processor)
}

fn parse_evidence_bytes(evidence: &[u8]) -> Result<SnpEvidence> {
    if let Ok(s) = std::str::from_utf8(evidence) {
        if s.trim_start().starts_with('{') {
            let ev: SnpEvidence = serde_json::from_str(s).context("parse SNP evidence JSON")?;
            return Ok(ev);
        }
    }

    let report = AttestationReport::from_bytes(evidence).context("parse SNP report bytes")?;
    Ok(SnpEvidence {
        attestation_report: report,
        cert_chain: None,
    })
}

fn verify_supplied_cert_chain(
    chain: Vec<CertTableEntry>,
    vendor_certs: &VendorCertificates,
) -> Result<Certificate> {
    let mut ask: Option<Certificate> = None;
    let mut ark: Option<Certificate> = None;
    let mut vek: Option<Certificate> = None;
    let mut vek_type = VendorEndorsementKey::Vcek;

    for cert in &chain {
        match cert.cert_type {
            CertType::ARK => {
                let provisioned_ark = vendor_certs.ark.clone();
                ark = Some(Certificate::from_bytes(cert.data.as_slice())?);
                (&provisioned_ark, &ark.clone().unwrap())
                    .verify()
                    .context("Provided ARK has an invalid signature")?;
            }
            CertType::ASK => {
                ask = Some(Certificate::from_bytes(cert.data.as_slice())?);
            }
            CertType::VCEK => {
                if vek.is_none() {
                    vek = Some(Certificate::from_bytes(cert.data.as_slice())?);
                }
            }
            CertType::VLEK => {
                if vek.is_none() {
                    vek_type = VendorEndorsementKey::Vlek;
                    vek = Some(Certificate::from_bytes(cert.data.as_slice())?);
                }
            }
            _ => continue,
        }
    }

    let vek = vek
        .as_ref()
        .ok_or_else(|| anyhow!("If a cert chain is provided, it must include a VCEK/VLEK"))?;

    let chain = Chain {
        ca: CaChain {
            ark: ark.unwrap_or_else(|| vendor_certs.ark.clone()),
            ask: ask.unwrap_or_else(|| match vek_type {
                VendorEndorsementKey::Vlek => vendor_certs.asvk.clone(),
                VendorEndorsementKey::Vcek => vendor_certs.ask.clone(),
            }),
        },
        vek: vek.clone(),
    };

    chain
        .verify()
        .context("Certificate chain provided by user failed to verify")?;

    Ok(vek.clone())
}

fn verify_fetched_vcek(vcek_der: &[u8], vendor_certs: &VendorCertificates) -> Result<Certificate> {
    let vcek = Certificate::from_bytes(vcek_der)
        .context("Failed to convert host VCEK into certificate")?;

    let chain = Chain {
        ca: CaChain {
            ark: vendor_certs.ark.clone(),
            ask: vendor_certs.ask.clone(),
        },
        vek: vcek.clone(),
    };

    chain
        .verify()
        .context("Certificate chain from host VCEK failed verification")?;

    Ok(vcek)
}

fn extract_verified_vek_meta(
    vek: &Certificate,
    processor: ProcessorGeneration,
) -> Result<HostVerifiedVekMeta> {
    let endorsement_key_der = vek.to_der()?;
    let parsed_endorsement_key = X509Certificate::from_der(&endorsement_key_der)?
        .1
        .tbs_certificate;

    let common_name =
        get_common_name(&vek.clone().into()).context("No common name found in certificate")?;

    let vek_kind = match common_name.as_str() {
        "VCEK" | "SEV-VCEK" => HostVekKind::Vcek,
        "VLEK" | "SEV-VLEK" => HostVekKind::Vlek,
        other => bail!("Unexpected endorsement key common name: {other}"),
    };

    let hw_id = match vek_kind {
        HostVekKind::Vcek => {
            Some(get_oid_octets::<64>(&parsed_endorsement_key, HW_ID_OID)?.to_vec())
        }
        HostVekKind::Vlek => None,
    };

    let fmc_spl = match processor {
        ProcessorGeneration::Turin => Some(get_oid_int(&parsed_endorsement_key, FMC_SPL_OID)?),
        _ => None,
    };

    Ok(HostVerifiedVekMeta {
        vek_kind,
        hw_id,
        bootloader_spl: get_oid_int(&parsed_endorsement_key, LOADER_SPL_OID)?,
        tee_spl: get_oid_int(&parsed_endorsement_key, TEE_SPL_OID)?,
        snp_spl: get_oid_int(&parsed_endorsement_key, SNP_SPL_OID)?,
        microcode_spl: get_oid_int(&parsed_endorsement_key, UCODE_SPL_OID)?,
        fmc_spl,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

fn map_processor_generation(processor: HostProcessorGeneration) -> ProcessorGeneration {
    match processor {
        HostProcessorGeneration::Milan => ProcessorGeneration::Milan,
        HostProcessorGeneration::Genoa => ProcessorGeneration::Genoa,
        HostProcessorGeneration::Turin => ProcessorGeneration::Turin,
    }
}

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
            0x10..=0x1F | 0xA0..=0xAF => Ok(ProcessorGeneration::Genoa),
            _ => Err(anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcessorGeneration::Turin),
            _ => Err(anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow!("Processor family not supported")),
    }
}

fn get_oid_octets<const N: usize>(
    vcek: &x509_parser::certificate::TbsCertificate,
    oid: Oid,
) -> Result<[u8; N]> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    if val.len() == N {
        return Ok(val.try_into().unwrap());
    }

    let (_, val_octet) = OctetString::from_der(val)?;
    val_octet
        .as_ref()
        .try_into()
        .context("Unexpected data size")
}

fn get_oid_int(cert: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = cert
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

fn get_common_name(cert: &x509::X509) -> Result<String> {
    let mut entries = cert.subject_name().entries_by_nid(Nid::COMMONNAME);
    let Some(e) = entries.next() else {
        bail!("No CN found");
    };

    if entries.count() != 0 {
        bail!("No CN found");
    }

    Ok(e.data().as_utf8()?.to_string())
}
