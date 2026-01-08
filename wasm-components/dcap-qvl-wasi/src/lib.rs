use anyhow::{anyhow, bail, Context, Result};
use dcap_qvl::QuoteCollateralV3;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const DEFAULT_PCS_URL: &str = "https://api.trustedservices.intel.com";

#[derive(Clone, Debug)]
struct PcsEndpoints {
    base_url: String,
    tee: &'static str,
    fmspc: String,
    ca: &'static str,
}

impl PcsEndpoints {
    fn new(base_url: &str, for_sgx: bool, fmspc: String, ca: &'static str) -> Self {
        let tee = if for_sgx { "sgx" } else { "tdx" };
        let base_url = base_url
            .trim()
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_owned();
        Self {
            base_url,
            tee,
            fmspc,
            ca,
        }
    }

    fn url_pckcrl(&self) -> String {
        self.mk_url("sgx", &format!("pckcrl?ca={}&encoding=der", self.ca))
    }

    fn url_rootcacrl(&self) -> String {
        self.mk_url("sgx", "rootcacrl")
    }

    fn url_tcb(&self) -> String {
        self.mk_url(self.tee, &format!("tcb?fmspc={}", self.fmspc))
    }

    fn url_qe_identity(&self) -> String {
        self.mk_url(self.tee, "qe/identity?update=standard")
    }

    fn mk_url(&self, tee: &str, path: &str) -> String {
        format!("{}/{}/certification/v4/{}", self.base_url, tee, path)
    }
}

fn cache_key(base_url: &str, tee: &str, fmspc: &str, ca: &str) -> String {
    let mut h = Sha256::new();
    h.update(base_url.as_bytes());
    let digest = h.finalize();
    let short = hex::encode(&digest[..4]);
    format!("collateral_{short}_{tee}_{fmspc}_{ca}.json")
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs())
}

fn read_cache(cache_path: &Path) -> Option<QuoteCollateralV3> {
    let data = fs::read(cache_path).ok()?;
    serde_json::from_slice(&data).ok()
}

fn write_cache(cache_path: &Path, collateral: &QuoteCollateralV3) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let data = serde_json::to_vec(collateral).context("serialize collateral")?;
    fs::write(cache_path, data).with_context(|| format!("write {}", cache_path.display()))?;
    Ok(())
}

fn cached_collateral_is_fresh(collateral: &QuoteCollateralV3, now_secs: u64) -> bool {
    let tcb_info_json: serde_json::Value = match serde_json::from_str(&collateral.tcb_info) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let next_update = tcb_info_json
        .get("nextUpdate")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let next_update = chrono::DateTime::parse_from_rfc3339(next_update);
    match next_update {
        Ok(dt) => now_secs <= dt.timestamp().max(0) as u64,
        Err(_) => false,
    }
}

#[cfg(feature = "wasi-http")]
fn http_get_bytes(url: &str) -> Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    use waki::Client;
    let resp = Client::new()
        .get(url)
        .send()
        .with_context(|| format!("HTTP GET {}", url))?;
    let status = resp.status_code();
    let mut hdrs = Vec::new();
    for (name, value) in resp.headers().iter() {
        hdrs.push((
            name.to_string(),
            value.to_str().unwrap_or_default().to_string(),
        ));
    }
    let body = resp.body().context("read response body")?;
    Ok((status, body, hdrs))
}

#[cfg(not(feature = "wasi-http"))]
fn http_get_bytes(_url: &str) -> Result<(u16, Vec<u8>, Vec<(String, String)>)> {
    bail!("dcap-qvl-wasi built without `wasi-http` support");
}

fn get_header(headers: &[(String, String)], name: &str) -> Result<String> {
    let (_, value) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .ok_or_else(|| anyhow!("Missing {name}"))?;
    let value = urlencoding::decode(value)?;
    Ok(value.into_owned())
}

fn try_decode_hex_crl(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = core::str::from_utf8(bytes).ok()?;
    hex::decode(s.trim()).ok()
}

fn extract_root_crl_from_chain(pck_crl_issuer_chain: &str) -> Result<Vec<u8>> {
    use der::Decode as DerDecode;
    use pem::Pem;
    use x509_cert::{
        ext::pkix::{
            name::{DistributionPointName, GeneralName},
            CrlDistributionPoints,
        },
        Certificate,
    };

    fn extract_crl_url(cert_der: &[u8]) -> Result<Option<String>> {
        let cert: Certificate = DerDecode::from_der(cert_der).context("parse certificate")?;
        let Some(extensions) = &cert.tbs_certificate.extensions else {
            return Ok(None);
        };
        for ext in extensions.iter() {
            if ext.extn_id.to_string() != "2.5.29.31" {
                continue;
            }
            let crl_dist_points: CrlDistributionPoints =
                DerDecode::from_der(ext.extn_value.as_bytes()).context("parse CRL DP")?;

            for dist_point in crl_dist_points.0.iter() {
                let Some(dist_point_name) = &dist_point.distribution_point else {
                    continue;
                };
                let DistributionPointName::FullName(general_names) = dist_point_name else {
                    continue;
                };
                for general_name in general_names.iter() {
                    let GeneralName::UniformResourceIdentifier(uri) = general_name else {
                        continue;
                    };
                    return Ok(Some(uri.to_string()));
                }
            }
        }
        Ok(None)
    }

    let pem_chain = pck_crl_issuer_chain.as_bytes();
    let blocks = pem::parse_many(pem_chain).context("parse issuer chain PEM")?;
    let root: &Pem = blocks.last().context("no certs in issuer chain")?;
    let Some(url) = extract_crl_url(root.contents())? else {
        bail!("Could not find CRL distribution point in root certificate");
    };
    let (status, body, _) = http_get_bytes(&url)?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch {url}: HTTP {status}");
    }
    Ok(body)
}

fn fetch_collateral_uncached(endpoints: &PcsEndpoints) -> Result<QuoteCollateralV3> {
    // PCK CRL
    let (status, pck_crl, headers) = http_get_bytes(&endpoints.url_pckcrl())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch PCK CRL: HTTP {status}");
    }
    let pck_crl_issuer_chain = get_header(&headers, "SGX-PCK-CRL-Issuer-Chain")?;

    // TCB info
    let (status, raw_tcb_info, headers) = http_get_bytes(&endpoints.url_tcb())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch TCB info: HTTP {status}");
    }
    let tcb_info_issuer_chain = get_header(&headers, "SGX-TCB-Info-Issuer-Chain")
        .or(get_header(&headers, "TCB-Info-Issuer-Chain"))?;
    let raw_tcb_info = String::from_utf8(raw_tcb_info).context("TCB info must be UTF-8")?;

    // QE identity
    let (status, raw_qe_identity, headers) = http_get_bytes(&endpoints.url_qe_identity())?;
    if !(200..300).contains(&status) {
        bail!("Failed to fetch QE identity: HTTP {status}");
    }
    let qe_identity_issuer_chain = get_header(&headers, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity =
        String::from_utf8(raw_qe_identity).context("QE identity must be UTF-8")?;

    // Root CA CRL: try PCCS endpoint first (may return hex-encoded bytes), else CRL DP from root cert.
    let mut root_ca_crl = None;
    if !endpoints.base_url.starts_with(DEFAULT_PCS_URL) {
        if let Ok((status, bytes, _)) = http_get_bytes(&endpoints.url_rootcacrl()) {
            if (200..300).contains(&status) {
                root_ca_crl = try_decode_hex_crl(&bytes).or(Some(bytes));
            }
        }
    }
    let root_ca_crl = match root_ca_crl {
        Some(v) => v,
        None => extract_root_crl_from_chain(&pck_crl_issuer_chain)?,
    };

    // Parse TCB info and QE identity payloads (extract and hex-decode "signature" field).
    let tcb_info_json: serde_json::Value =
        serde_json::from_str(&raw_tcb_info).context("TCB info should be valid JSON")?;
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json
        .get("signature")
        .and_then(|v| v.as_str())
        .context("TCB info missing 'signature'")?;
    let tcb_info_signature =
        hex::decode(tcb_info_signature).context("TCB info signature must be hex")?;

    let qe_identity_json: serde_json::Value =
        serde_json::from_str(&raw_qe_identity).context("QE identity should be valid JSON")?;
    let qe_identity = qe_identity_json
        .get("enclaveIdentity")
        .context("QE identity missing 'enclaveIdentity'")?
        .to_string();
    let qe_identity_signature = qe_identity_json
        .get("signature")
        .and_then(|v| v.as_str())
        .context("QE identity missing 'signature'")?;
    let qe_identity_signature =
        hex::decode(qe_identity_signature).context("QE identity signature must be hex")?;

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
    })
}

pub fn get_collateral_cached(pccs_url: Option<&str>, quote: &[u8], cache_dir: &Path) -> Result<QuoteCollateralV3> {
    let pccs_url = pccs_url.unwrap_or(DEFAULT_PCS_URL);

    let quote_obj = dcap_qvl::quote::Quote::parse(quote).context("parse quote")?;
    let ca = quote_obj.ca().context("get CA")?;
    let fmspc = hex::encode_upper(quote_obj.fmspc().context("get FMSPC")?);
    let for_sgx = quote_obj.header.is_sgx();

    let endpoints = PcsEndpoints::new(pccs_url, for_sgx, fmspc.clone(), ca);
    let key = cache_key(&endpoints.base_url, endpoints.tee, &fmspc, ca);
    let cache_path: PathBuf = cache_dir.join(key);

    let now = now_secs()?;
    if let Some(cached) = read_cache(&cache_path) {
        if cached_collateral_is_fresh(&cached, now) {
            return Ok(cached);
        }
    }

    let collateral = fetch_collateral_uncached(&endpoints)?;
    write_cache(&cache_path, &collateral)?;
    Ok(collateral)
}
