use crate::VerifyOptions;
use ::cmw::{
    collection::Label as ExternalCmwLabel, Indicator as ExternalCmwIndicator, CMW as ExternalCmw,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::{Integer, Value as CborValue};
use futures_util::TryStreamExt;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    future::Future,
    io::ErrorKind,
    path::PathBuf,
};
use wasm_pkg_client::{
    oci::{client::ClientProtocol as WasmPkgClientProtocol, OciRegistryConfig},
    Client as WasmPkgClient, Config as WasmPkgConfig, CustomConfig as WasmPkgCustomConfig,
    PackageRef as WasmPkgPackageRef, Registry as WasmPkgRegistry,
    RegistryMapping as WasmPkgRegistryMapping, RegistryMetadata as WasmPkgRegistryMetadata,
    Version as WasmPkgVersion,
};

pub const TRUSTMEE_COLLECTION_TYPE: &str = "https://trustmee.invalid/cmw/verification-input";
pub const TRUSTMEE_EAT_PROFILE: &str = "https://trustmee.invalid/eat/component-evidence";
pub const DEFAULT_COMPONENT_OCI_BASE: &str =
    "oci://registry.example.com/trustmee/verifier-components";
pub const WASM_MEDIA_TYPE: &str = "application/wasm";
pub const SNP_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.snp-collateral+cbor";
pub const TDX_COLLATERAL_MEDIA_TYPE: &str = "application/vnd.trustmee.tdx-collateral+cbor";

const EAT_MEDIA_TYPE_CBOR: &str = "application/eat-ucs+cbor";
const EAT_MEDIA_TYPE_JSON: &str = "application/eat-ucs+json";
const COMPONENT_ID_PREFIX: &str = "component-";
const TRUSTMEE_CBOR_KEY_EAT_PROFILE: u64 = 265;
const TRUSTMEE_CBOR_KEY_COMPONENT_ID: u64 = 65537;
const TRUSTMEE_CBOR_KEY_EVIDENCE_TYPE: u64 = 65538;
const TRUSTMEE_CBOR_KEY_EVIDENCE: u64 = 65539;
const COMPONENT_CACHE_SUBDIR: &str = "components";

fn cache_trace_enabled() -> bool {
    std::env::var("TRUSTMEE_CACHE_TRACE")
        .map(|value| {
            value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ComponentEndorsement {
    pub(crate) label: String,
    pub(crate) media_type: String,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ComponentVerifierInput {
    pub(crate) evidence: Vec<u8>,
    pub(crate) evidence_media_type: String,
    pub(crate) endorsements: Vec<ComponentEndorsement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedCmwInput {
    pub(crate) component_id: String,
    pub(crate) stapled_component_records: Vec<StapledComponentRecord>,
    pub(crate) verifier_input: ComponentVerifierInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StapledComponentRecord {
    pub(crate) label: String,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CmwCollection {
    collection_type: String,
    records: Vec<CmwRecord>,
}

#[derive(Clone, Debug)]
struct CmwRecord {
    label: String,
    media_type: String,
    payload: Vec<u8>,
    indicator: u64,
}

#[derive(Clone, Debug)]
struct TrustMeeEat {
    component_id: String,
    evidence: Vec<u8>,
    evidence_media_type: String,
}

#[derive(Clone, Debug)]
struct ParsedMediaType {
    base: String,
    params: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordRole {
    Evidence,
    Endorsement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentRepositoryProtocol {
    Http,
    Https,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ComponentRepository {
    Local {
        root: PathBuf,
        package: WasmPkgPackageRef,
    },
    Remote {
        registry: WasmPkgRegistry,
        package: WasmPkgPackageRef,
        namespace_prefix: Option<String>,
        protocol: ComponentRepositoryProtocol,
    },
}

pub(crate) fn parse_cmw_input(bytes: &[u8]) -> Result<ParsedCmwInput> {
    let collection = parse_cmw_collection(bytes).context("parse CMW collection")?;
    if collection.collection_type != TRUSTMEE_COLLECTION_TYPE {
        bail!(
            "unsupported CMW collection type `{}`; expected `{}`",
            collection.collection_type,
            TRUSTMEE_COLLECTION_TYPE
        );
    }

    let mut evidence_record: Option<CmwRecord> = None;
    let mut endorsement_records = Vec::new();
    for record in collection.records {
        match classify_indicator(record.indicator)
            .with_context(|| format!("invalid indicator for CMW entry `{}`", record.label))?
        {
            RecordRole::Evidence => {
                if evidence_record.replace(record).is_some() {
                    bail!("CMW collection must contain exactly one Evidence entry");
                }
            }
            RecordRole::Endorsement => endorsement_records.push(record),
        }
    }

    let evidence_record = evidence_record
        .ok_or_else(|| anyhow!("CMW collection must contain exactly one Evidence entry"))?;
    let eat = parse_trustmee_eat(&evidence_record).context("parse TrustMee EAT")?;
    let (stapled_component_records, endorsements) =
        split_component_endorsements(endorsement_records)
            .context("parse verifier component endorsements")?;

    Ok(ParsedCmwInput {
        component_id: eat.component_id,
        stapled_component_records,
        verifier_input: ComponentVerifierInput {
            evidence: eat.evidence,
            evidence_media_type: eat.evidence_media_type,
            endorsements,
        },
    })
}

pub(crate) fn component_id_for_bytes(bytes: &[u8]) -> String {
    format!(
        "{COMPONENT_ID_PREFIX}{}",
        hex::encode(Sha256::digest(bytes))
    )
}

pub(crate) fn component_hash_for_id(component_id: &str) -> Result<[u8; 32]> {
    validate_component_id(component_id)?;

    let digest = component_id
        .strip_prefix(COMPONENT_ID_PREFIX)
        .ok_or_else(|| anyhow!("component_id must start with `{COMPONENT_ID_PREFIX}`"))?;
    let mut component_hash = [0u8; 32];
    hex::decode_to_slice(digest, &mut component_hash).context("decode component_id digest")?;
    Ok(component_hash)
}

fn parse_cmw_collection(bytes: &[u8]) -> Result<CmwCollection> {
    if looks_like_json(bytes) {
        // Keep the existing TrustMee JSON collection parser as-is.
        parse_json_cmw_collection(bytes)
    } else {
        // Use rust-cmw for the generic CBOR wrapper layer.
        parse_cbor_cmw_collection(bytes)
    }
}

fn looks_like_json(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte == b'{' || byte == b'[')
        .unwrap_or(false)
}

fn parse_json_cmw_collection(bytes: &[u8]) -> Result<CmwCollection> {
    let value: JsonValue = serde_json::from_slice(bytes).context("parse JSON CMW collection")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("JSON CMW collection must be a JSON object"))?;

    let collection_type = object
        .get("__cmwc_t")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("JSON CMW collection must include string `__cmwc_t`"))?
        .to_string();

    let mut records = Vec::new();
    for (label, value) in object {
        if label == "__cmwc_t" {
            continue;
        }
        records.push(parse_json_record(label, value)?);
    }

    if records.is_empty() {
        bail!("CMW collection must contain at least one entry");
    }

    Ok(CmwCollection {
        collection_type,
        records,
    })
}

fn parse_json_record(label: &str, value: &JsonValue) -> Result<CmwRecord> {
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("JSON CMW entry `{label}` must be an array"))?;
    if !(items.len() == 2 || items.len() == 3) {
        bail!("JSON CMW entry `{label}` must have 2 or 3 items");
    }

    let media_type = items[0]
        .as_str()
        .ok_or_else(|| anyhow!("JSON CMW entry `{label}` media type must be a string"))?
        .to_string();
    let payload_b64 = items[1]
        .as_str()
        .ok_or_else(|| anyhow!("JSON CMW entry `{label}` payload must be a base64url string"))?;
    let payload = decode_base64url(payload_b64)
        .with_context(|| format!("decode JSON CMW payload for `{label}`"))?;
    let indicator = parse_indicator_json(label, items.get(2))?;

    Ok(CmwRecord {
        label: label.to_string(),
        media_type,
        payload,
        indicator,
    })
}

fn parse_indicator_json(label: &str, value: Option<&JsonValue>) -> Result<u64> {
    let value =
        value.ok_or_else(|| anyhow!("JSON CMW entry `{label}` must include an indicator"))?;
    value
        .as_u64()
        .ok_or_else(|| anyhow!("JSON CMW entry `{label}` indicator must be an unsigned integer"))
}

fn parse_cbor_cmw_collection(bytes: &[u8]) -> Result<CmwCollection> {
    let cmw = ExternalCmw::unmarshal_cbor(bytes).context("parse CBOR CMW collection")?;
    let collection = match cmw {
        ExternalCmw::Collection(collection) => collection,
        ExternalCmw::Monad(_) => bail!("CBOR CMW collection must be a map"),
    };

    let collection_type = collection
        .get_type()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("CBOR CMW collection must include `__cmwc_t`"))?;

    let mut records = Vec::new();
    for meta in collection.get_meta() {
        let label = external_cmw_label_to_string(&meta.key);
        let record = collection
            .get_item(&meta.key)
            .ok_or_else(|| anyhow!("CBOR CMW entry `{label}` is missing"))?;
        records.push(parse_external_cmw_record(&label, record)?);
    }

    if records.is_empty() {
        bail!("CMW collection must contain at least one entry");
    }

    Ok(CmwCollection {
        collection_type,
        records,
    })
}

fn external_cmw_label_to_string(label: &ExternalCmwLabel) -> String {
    match label {
        ExternalCmwLabel::Str(text) => text.clone(),
        ExternalCmwLabel::Uint(value) => value.to_string(),
    }
}

fn parse_external_cmw_record(label: &str, record: &ExternalCmw) -> Result<CmwRecord> {
    let monad = match record {
        ExternalCmw::Monad(monad) => monad,
        ExternalCmw::Collection(_) => {
            bail!("CBOR CMW entry `{label}` must be a monad record");
        }
    };

    let indicator = monad
        .indicator()
        .map(|value| u64::from(value.bits()))
        .ok_or_else(|| anyhow!("CBOR CMW entry `{label}` must include an indicator"))?;

    Ok(CmwRecord {
        label: label.to_string(),
        media_type: monad.type_(),
        payload: monad.value(),
        indicator,
    })
}

fn classify_indicator(indicator: u64) -> Result<RecordRole> {
    let evidence_indicator = u64::from(ExternalCmwIndicator::EVIDENCE.bits());
    let endorsement_indicator = u64::from(ExternalCmwIndicator::ENDORSEMENTS.bits());

    match indicator {
        value if value == evidence_indicator => Ok(RecordRole::Evidence),
        value if value == endorsement_indicator => Ok(RecordRole::Endorsement),
        _ => bail!(
            "unsupported CMW indicator `{indicator}`; expected Evidence ({evidence_indicator}) or Endorsement ({endorsement_indicator})"
        ),
    }
}

fn parse_trustmee_eat(record: &CmwRecord) -> Result<TrustMeeEat> {
    let media_type = parse_media_type(&record.media_type)
        .with_context(|| format!("parse media type for `{}`", record.label))?;
    let eat_profile = media_type
        .params
        .get("eat_profile")
        .ok_or_else(|| anyhow!("TrustMee EAT media type must include `eat_profile` parameter"))?;
    if eat_profile != TRUSTMEE_EAT_PROFILE {
        bail!("unsupported EAT profile `{eat_profile}`; expected `{TRUSTMEE_EAT_PROFILE}`");
    }

    match media_type.base.as_str() {
        EAT_MEDIA_TYPE_JSON => parse_json_trustmee_eat(&record.payload),
        EAT_MEDIA_TYPE_CBOR => parse_cbor_trustmee_eat(&record.payload),
        other => bail!(
            "unsupported Evidence media type `{other}`; expected `{EAT_MEDIA_TYPE_JSON}` or `{EAT_MEDIA_TYPE_CBOR}`"
        ),
    }
}

fn parse_json_trustmee_eat(bytes: &[u8]) -> Result<TrustMeeEat> {
    let value: JsonValue = serde_json::from_slice(bytes).context("parse JSON EAT payload")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("JSON EAT payload must be a JSON object"))?;

    let eat_profile = json_required_str(object, "eat_profile")?;
    if eat_profile != TRUSTMEE_EAT_PROFILE {
        bail!("unsupported EAT payload profile `{eat_profile}`; expected `{TRUSTMEE_EAT_PROFILE}`");
    }

    let component_id = json_required_str(object, "component_id")?.to_string();
    validate_component_id(&component_id)?;

    let evidence_media_type = json_required_str(object, "evidence_type")?.to_string();
    let evidence = decode_base64url(json_required_str(object, "evidence")?)
        .context("decode TrustMee EAT evidence bytes")?;

    Ok(TrustMeeEat {
        component_id,
        evidence,
        evidence_media_type,
    })
}

fn json_required_str<'a>(
    object: &'a serde_json::Map<String, JsonValue>,
    key: &str,
) -> Result<&'a str> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow!("JSON EAT payload must include string `{key}`"))
}

fn parse_cbor_trustmee_eat(bytes: &[u8]) -> Result<TrustMeeEat> {
    let value: CborValue = ciborium::from_reader(bytes).context("parse CBOR EAT payload")?;
    let claims = value
        .as_map()
        .ok_or_else(|| anyhow!("CBOR EAT payload must be a map"))?;

    let mut eat_profile = None;
    let mut component_id = None;
    let mut evidence = None;
    let mut evidence_type = None;

    for (key, value) in claims {
        match parse_cbor_eat_claim_key(key)? {
            Some(TrustMeeEatClaimKey::EatProfile) => {
                eat_profile = Some(cbor_required_text_value("eat_profile", value)?)
            }
            Some(TrustMeeEatClaimKey::ComponentId) => {
                component_id = Some(cbor_required_text_value("component_id", value)?)
            }
            Some(TrustMeeEatClaimKey::EvidenceType) => {
                evidence_type = Some(cbor_required_text_value("evidence_type", value)?)
            }
            Some(TrustMeeEatClaimKey::Evidence) => {
                evidence = Some(cbor_required_bytes_value("evidence", value)?)
            }
            None => {}
        }
    }

    let eat_profile =
        eat_profile.ok_or_else(|| anyhow!("CBOR EAT payload must include `eat_profile`"))?;
    if eat_profile != TRUSTMEE_EAT_PROFILE {
        bail!(
            "unsupported EAT payload profile `{}`; expected `{}`",
            eat_profile,
            TRUSTMEE_EAT_PROFILE
        );
    }
    let component_id =
        component_id.ok_or_else(|| anyhow!("CBOR EAT payload must include `component_id`"))?;
    validate_component_id(&component_id)?;
    let evidence_type =
        evidence_type.ok_or_else(|| anyhow!("CBOR EAT payload must include `evidence_type`"))?;
    let evidence = evidence.ok_or_else(|| anyhow!("CBOR EAT payload must include `evidence`"))?;

    Ok(TrustMeeEat {
        component_id,
        evidence,
        evidence_media_type: evidence_type,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustMeeEatClaimKey {
    EatProfile,
    ComponentId,
    EvidenceType,
    Evidence,
}

fn parse_cbor_eat_claim_key(value: &CborValue) -> Result<Option<TrustMeeEatClaimKey>> {
    match value {
        CborValue::Text(text) => Ok(match text.as_str() {
            "eat_profile" => Some(TrustMeeEatClaimKey::EatProfile),
            "component_id" => Some(TrustMeeEatClaimKey::ComponentId),
            "evidence_type" => Some(TrustMeeEatClaimKey::EvidenceType),
            "evidence" => Some(TrustMeeEatClaimKey::Evidence),
            _ => None,
        }),
        CborValue::Integer(value) => Ok(match integer_to_u64(*value)? {
            TRUSTMEE_CBOR_KEY_EAT_PROFILE => Some(TrustMeeEatClaimKey::EatProfile),
            TRUSTMEE_CBOR_KEY_COMPONENT_ID => Some(TrustMeeEatClaimKey::ComponentId),
            TRUSTMEE_CBOR_KEY_EVIDENCE_TYPE => Some(TrustMeeEatClaimKey::EvidenceType),
            TRUSTMEE_CBOR_KEY_EVIDENCE => Some(TrustMeeEatClaimKey::Evidence),
            _ => None,
        }),
        _ => bail!("CBOR EAT claim keys must be text or non-negative integers"),
    }
}

fn cbor_required_text_value(label: &str, value: &CborValue) -> Result<String> {
    value
        .as_text()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("CBOR EAT claim `{label}` must be a text string"))
}

fn cbor_required_bytes_value(label: &str, value: &CborValue) -> Result<Vec<u8>> {
    if let Some(bytes) = value.as_bytes() {
        return Ok(bytes.to_vec());
    }

    if let Some(values) = value.as_array() {
        let mut bytes = Vec::with_capacity(values.len());
        for item in values {
            let integer = item.as_integer().ok_or_else(|| {
                anyhow!("CBOR EAT claim `{label}` byte array entries must be integers")
            })?;
            let value = integer_to_u64(integer)?;
            let value = u8::try_from(value).map_err(|_| {
                anyhow!("CBOR EAT claim `{label}` byte array entries must fit in u8")
            })?;
            bytes.push(value);
        }
        return Ok(bytes);
    }

    bail!("CBOR EAT claim `{label}` must be a byte string")
}

fn integer_to_u64(value: Integer) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow!("expected a non-negative integer value"))
}

fn validate_component_id(component_id: &str) -> Result<()> {
    let digest = component_id
        .strip_prefix(COMPONENT_ID_PREFIX)
        .ok_or_else(|| anyhow!("component_id must start with `{COMPONENT_ID_PREFIX}`"))?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        bail!("component_id must contain a lowercase SHA-256 digest");
    }
    Ok(())
}

fn split_component_endorsements(
    endorsement_records: Vec<CmwRecord>,
) -> Result<(Vec<StapledComponentRecord>, Vec<ComponentEndorsement>)> {
    let mut stapled_component_records = Vec::new();
    let mut endorsements = Vec::new();

    for record in endorsement_records {
        let parsed_media_type = parse_media_type(&record.media_type)
            .with_context(|| format!("parse endorsement media type for `{}`", record.label))?;

        if parsed_media_type.base == WASM_MEDIA_TYPE {
            stapled_component_records.push(StapledComponentRecord {
                label: record.label,
                payload: record.payload,
            });
            continue;
        }

        endorsements.push(ComponentEndorsement {
            label: record.label,
            media_type: record.media_type,
            payload: record.payload,
        });
    }

    Ok((stapled_component_records, endorsements))
}

pub(crate) fn resolve_component_bytes(
    component_id: &str,
    stapled_component_records: Vec<StapledComponentRecord>,
    options: &VerifyOptions,
) -> Result<Vec<u8>> {
    if let Some(component_bytes) =
        resolve_stapled_component(component_id, stapled_component_records)?
    {
        if cache_trace_enabled() {
            eprintln!("CMW component source: STAPLED component for `{component_id}`");
        }
        cache_component_bytes(component_id, &component_bytes, options)?;
        return Ok(component_bytes);
    }

    if let Some(component_bytes) = load_component_from_cache(component_id, options)? {
        return Ok(component_bytes);
    }

    let component_bytes = fetch_component_from_oci(component_id, options.component_repository_hint.as_deref())
        .with_context(|| {
            format!(
                "missing wasm component for `{component_id}`: no matching local cache entry and no stapled `application/wasm` endorsement"
            )
        })?;
    if cache_trace_enabled() {
        eprintln!("CMW component source: OCI fetch for `{component_id}`");
    }
    cache_component_bytes(component_id, &component_bytes, options)?;
    Ok(component_bytes)
}

fn resolve_stapled_component(
    component_id: &str,
    stapled_component_records: Vec<StapledComponentRecord>,
) -> Result<Option<Vec<u8>>> {
    let mut stapled_component = None;

    for record in stapled_component_records {
        let record_component_id = component_id_for_bytes(&record.payload);
        if record_component_id != component_id {
            bail!(
                "stapled Wasm component `{}` has component_id `{record_component_id}`, expected `{component_id}`",
                record.label
            );
        }
        if stapled_component.replace(record.payload).is_some() {
            bail!("CMW collection must not include more than one matching stapled Wasm component");
        }
    }

    Ok(stapled_component)
}

fn component_cache_dir(options: &VerifyOptions) -> PathBuf {
    options.cache_dir.join(COMPONENT_CACHE_SUBDIR)
}

fn component_cache_path(component_id: &str, options: &VerifyOptions) -> PathBuf {
    component_cache_dir(options).join(format!("{component_id}.wasm"))
}

fn load_component_from_cache(
    component_id: &str,
    options: &VerifyOptions,
) -> Result<Option<Vec<u8>>> {
    let path = component_cache_path(component_id, options);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if cache_trace_enabled() {
                eprintln!(
                    "CMW component cache: DISK MISS for `{component_id}` at `{}`",
                    path.display()
                );
            }
            return Ok(None);
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };

    let cached_component_id = component_id_for_bytes(&bytes);
    if cached_component_id != component_id {
        bail!(
            "cached Wasm component digest mismatch at `{}`: expected `{component_id}`, got `{cached_component_id}`",
            path.display()
        );
    }

    if cache_trace_enabled() {
        eprintln!(
            "CMW component cache: DISK HIT for `{component_id}` at `{}`",
            path.display()
        );
    }

    Ok(Some(bytes))
}

fn cache_component_bytes(component_id: &str, bytes: &[u8], options: &VerifyOptions) -> Result<()> {
    let resolved_component_id = component_id_for_bytes(bytes);
    if resolved_component_id != component_id {
        bail!(
            "cannot cache Wasm component: digest mismatch for `{component_id}`, got `{resolved_component_id}`"
        );
    }

    let path = component_cache_path(component_id, options);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    if cache_trace_enabled() {
        eprintln!(
            "CMW component cache: STORED `{component_id}` at `{}`",
            path.display()
        );
    }
    Ok(())
}

fn fetch_component_from_oci(component_id: &str, hint: Option<&str>) -> Result<Vec<u8>> {
    let base = hint.unwrap_or(DEFAULT_COMPONENT_OCI_BASE);
    let repository = parse_component_repository_base(base)
        .with_context(|| format!("parse OCI component repository base `{base}`"))?;
    let version = component_version_for_id(component_id)
        .with_context(|| format!("derive package version for `{component_id}`"))?;
    let bytes = run_async_result(fetch_component_bytes_via_wasm_pkg(repository, version))
        .context("fetch OCI component via wasm_pkg_client")?;

    let fetched_component_id = component_id_for_bytes(&bytes);
    if fetched_component_id != component_id {
        bail!(
            "fetched OCI component digest mismatch: expected `{component_id}`, got `{fetched_component_id}`"
        );
    }

    Ok(bytes)
}

fn component_version_for_id(component_id: &str) -> Result<WasmPkgVersion> {
    validate_component_id(component_id)?;
    let digest = component_id
        .strip_prefix(COMPONENT_ID_PREFIX)
        .ok_or_else(|| anyhow!("component_id must start with `{COMPONENT_ID_PREFIX}`"))?;
    let version = format!("0.0.0-component.sha{digest}");
    version
        .parse()
        .with_context(|| format!("parse mapped package version `{version}`"))
}

fn parse_component_repository_base(base: &str) -> Result<ComponentRepository> {
    if let Some(rest) = base.strip_prefix("file://") {
        return parse_local_component_repository(rest);
    }
    if let Some(rest) = base.strip_prefix("oci+file://") {
        return parse_local_component_repository(rest);
    }
    if let Some(rest) = base.strip_prefix("oci+http://") {
        return parse_remote_component_repository(rest, ComponentRepositoryProtocol::Http);
    }
    if let Some(rest) = base.strip_prefix("http://") {
        return parse_remote_component_repository(rest, ComponentRepositoryProtocol::Http);
    }
    if let Some(rest) = base.strip_prefix("oci+https://") {
        return parse_remote_component_repository(rest, ComponentRepositoryProtocol::Https);
    }
    if let Some(rest) = base.strip_prefix("https://") {
        return parse_remote_component_repository(rest, ComponentRepositoryProtocol::Https);
    }
    if let Some(rest) = base.strip_prefix("oci://") {
        return parse_remote_component_repository(rest, ComponentRepositoryProtocol::Https);
    }

    bail!("OCI repository base must start with `oci://`, `https://`, `http://`, or `file://`");
}

fn parse_local_component_repository(rest: &str) -> Result<ComponentRepository> {
    let repository_path = rest.trim_end_matches('/');
    if repository_path.is_empty() {
        bail!("file OCI repository base must include a path");
    }
    if !repository_path.starts_with('/') {
        bail!("file OCI repository base must use an absolute path");
    }

    let mut path = PathBuf::from(repository_path);
    let package_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("file OCI repository base must include a package path"))?
        .to_string();
    path.pop();
    let package_namespace = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("file OCI repository base must include a namespace and package"))?
        .to_string();
    path.pop();

    Ok(ComponentRepository::Local {
        root: path,
        package: make_component_package_ref(&package_namespace, &package_name)?,
    })
}

fn parse_remote_component_repository(
    rest: &str,
    protocol: ComponentRepositoryProtocol,
) -> Result<ComponentRepository> {
    let rest = rest.trim_end_matches('/');
    let (registry, path) = rest
        .split_once('/')
        .ok_or_else(|| anyhow!("OCI repository base must include a registry and package path"))?;
    let path_segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if path_segments.len() < 2 {
        bail!("OCI repository base must include at least `<namespace>/<package>`");
    }

    let package_namespace = path_segments[path_segments.len() - 2];
    let package_name = path_segments[path_segments.len() - 1];
    let namespace_prefix = if path_segments.len() > 2 {
        Some(format!(
            "{}/",
            path_segments[..path_segments.len() - 2].join("/")
        ))
    } else {
        None
    };

    Ok(ComponentRepository::Remote {
        registry: registry
            .parse()
            .with_context(|| format!("parse OCI registry `{registry}`"))?,
        package: make_component_package_ref(package_namespace, package_name)?,
        namespace_prefix,
        protocol,
    })
}

fn make_component_package_ref(namespace: &str, name: &str) -> Result<WasmPkgPackageRef> {
    Ok(WasmPkgPackageRef::new(
        namespace
            .parse()
            .with_context(|| format!("parse package namespace `{namespace}`"))?,
        name.parse()
            .with_context(|| format!("parse package name `{name}`"))?,
    ))
}

async fn fetch_component_bytes_via_wasm_pkg(
    repository: ComponentRepository,
    version: WasmPkgVersion,
) -> Result<Vec<u8>> {
    let (client, package) = build_wasm_pkg_client(repository)?;
    let release = client
        .get_release(&package, &version)
        .await
        .with_context(|| format!("resolve release `{package}@{version}`"))?;
    let mut stream = client
        .stream_content(&package, &release)
        .await
        .with_context(|| format!("open content stream for `{package}@{version}`"))?;

    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .with_context(|| format!("read content stream for `{package}@{version}`"))?
    {
        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes)
}

fn build_wasm_pkg_client(
    repository: ComponentRepository,
) -> Result<(WasmPkgClient, WasmPkgPackageRef)> {
    match repository {
        ComponentRepository::Local { root, package } => {
            let config = WasmPkgConfig::from_toml(&format!(
                r#"
[package_registry_overrides]
"{package}" = "local.trustmee.test"

[registry."local.trustmee.test"]
type = "local"
[registry."local.trustmee.test".local]
root = "{root}"
"#,
                package = package,
                root = root.display(),
            ))
            .context("build local wasm_pkg_client config")?;
            Ok((WasmPkgClient::new(config), package))
        }
        ComponentRepository::Remote {
            registry,
            package,
            namespace_prefix,
            protocol,
        } => {
            let mut protocol_configs: HashMap<String, serde_json::Map<String, serde_json::Value>> =
                HashMap::new();
            let mut oci_metadata = serde_json::Map::new();
            oci_metadata.insert(
                "registry".to_string(),
                JsonValue::String(registry.to_string()),
            );
            if let Some(namespace_prefix) = namespace_prefix {
                oci_metadata.insert(
                    "namespacePrefix".to_string(),
                    JsonValue::String(namespace_prefix),
                );
            }
            protocol_configs.insert("oci".to_string(), oci_metadata);

            let mut metadata = WasmPkgRegistryMetadata::default();
            metadata.preferred_protocol = Some("oci".to_string());
            metadata.protocol_configs = protocol_configs;

            let mut config = WasmPkgConfig::empty();
            config.set_package_registry_override(
                package.clone(),
                WasmPkgRegistryMapping::Custom(WasmPkgCustomConfig {
                    registry: registry.clone(),
                    metadata,
                }),
            );

            let registry_config = config.get_or_insert_registry_config_mut(&registry);
            registry_config.set_default_backend(Some("oci".to_string()));
            let mut client_config = wasm_pkg_client::oci::client::ClientConfig::default();
            client_config.protocol = match protocol {
                ComponentRepositoryProtocol::Http => WasmPkgClientProtocol::Http,
                ComponentRepositoryProtocol::Https => WasmPkgClientProtocol::Https,
            };
            registry_config
                .set_backend_config(
                    "oci",
                    OciRegistryConfig {
                        client_config,
                        credentials: None,
                    },
                )
                .context("configure OCI wasm_pkg_client backend")?;

            Ok((WasmPkgClient::new(config), package))
        }
    }
}

fn run_async_result<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create Tokio runtime for wasm_pkg_client")?;
    runtime.block_on(future)
}

fn parse_media_type(raw: &str) -> Result<ParsedMediaType> {
    let mut parts = raw.split(';');
    let base = parts
        .next()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow!("media type is empty"))?
        .to_ascii_lowercase();

    let mut params = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid media type parameter `{part}`"))?;
        let mut value = value.trim().to_string();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].to_string();
        }
        params.insert(key.trim().to_ascii_lowercase(), value);
    }

    Ok(ParsedMediaType { base, params })
}

fn decode_base64url(input: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
        .map_err(|err| anyhow!("invalid base64url data: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        classify_indicator, component_id_for_bytes, component_version_for_id,
        parse_cbor_trustmee_eat, parse_component_repository_base, parse_media_type, CborValue,
        ComponentRepository, ComponentRepositoryProtocol, ExternalCmwIndicator, Integer,
        RecordRole, DEFAULT_COMPONENT_OCI_BASE, TRUSTMEE_CBOR_KEY_COMPONENT_ID,
        TRUSTMEE_CBOR_KEY_EAT_PROFILE, TRUSTMEE_CBOR_KEY_EVIDENCE, TRUSTMEE_CBOR_KEY_EVIDENCE_TYPE,
        TRUSTMEE_EAT_PROFILE,
    };

    #[test]
    fn classify_indicator_accepts_supported_values() {
        assert_eq!(
            classify_indicator(u64::from(ExternalCmwIndicator::EVIDENCE.bits()))
                .expect("classify evidence"),
            RecordRole::Evidence
        );
        assert_eq!(
            classify_indicator(u64::from(ExternalCmwIndicator::ENDORSEMENTS.bits()))
                .expect("classify endorsement"),
            RecordRole::Endorsement
        );
    }

    #[test]
    fn component_id_is_digest_based() {
        let component_id = component_id_for_bytes(b"wasm bytes");
        assert!(component_id.starts_with("component-"));
        assert_eq!(component_id.len(), "component-".len() + 64);
    }

    #[test]
    fn parse_component_repository_base_defaults_to_placeholder_registry() {
        let parsed = parse_component_repository_base(DEFAULT_COMPONENT_OCI_BASE)
            .expect("parse default base");

        match parsed {
            ComponentRepository::Remote {
                registry,
                package,
                namespace_prefix,
                protocol,
            } => {
                assert_eq!(registry.to_string(), "registry.example.com");
                assert_eq!(package.to_string(), "trustmee:verifier-components");
                assert_eq!(namespace_prefix, None);
                assert_eq!(protocol, ComponentRepositoryProtocol::Https);
            }
            other => panic!("expected remote repository, got {other:?}"),
        }
    }

    #[test]
    fn parse_media_type_preserves_params() {
        let parsed = parse_media_type(
            "application/eat-ucs+json; eat_profile=\"https://trustmee.invalid/eat/component-evidence\"",
        )
        .expect("parse media type");
        assert_eq!(parsed.base, "application/eat-ucs+json");
        assert_eq!(
            parsed.params.get("eat_profile").map(String::as_str),
            Some("https://trustmee.invalid/eat/component-evidence")
        );
    }

    #[test]
    fn parse_component_repository_base_supports_http_override() {
        let parsed =
            parse_component_repository_base("oci+http://127.0.0.1:5000/trustmee/components")
                .expect("parse oci base");

        match parsed {
            ComponentRepository::Remote {
                registry,
                package,
                namespace_prefix,
                protocol,
            } => {
                assert_eq!(registry.to_string(), "127.0.0.1:5000");
                assert_eq!(package.to_string(), "trustmee:components");
                assert_eq!(namespace_prefix, None);
                assert_eq!(protocol, ComponentRepositoryProtocol::Http);
            }
            other => panic!("expected remote repository, got {other:?}"),
        }
    }

    #[test]
    fn parse_component_repository_base_supports_prefixes() {
        let parsed = parse_component_repository_base(
            "oci://ghcr.io/webassembly/trustmee/verifier-components",
        )
        .expect("parse OCI base");

        match parsed {
            ComponentRepository::Remote {
                registry,
                package,
                namespace_prefix,
                protocol,
            } => {
                assert_eq!(registry.to_string(), "ghcr.io");
                assert_eq!(package.to_string(), "trustmee:verifier-components");
                assert_eq!(namespace_prefix.as_deref(), Some("webassembly/"));
                assert_eq!(protocol, ComponentRepositoryProtocol::Https);
            }
            other => panic!("expected remote repository, got {other:?}"),
        }
    }

    #[test]
    fn parse_component_repository_base_supports_file_override() {
        let parsed = parse_component_repository_base("file:///tmp/trustmee/verifier-components")
            .expect("parse file base");

        match parsed {
            ComponentRepository::Local { root, package } => {
                assert_eq!(root, std::path::PathBuf::from("/tmp"));
                assert_eq!(package.to_string(), "trustmee:verifier-components");
            }
            other => panic!("expected local repository, got {other:?}"),
        }
    }

    #[test]
    fn component_version_for_id_maps_digest_to_semver() {
        let component_id =
            "component-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let version = component_version_for_id(component_id).expect("derive package version");
        assert_eq!(
            version.to_string(),
            "0.0.0-component.sha0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn component_version_for_id_rejects_invalid_component_id() {
        let err = component_version_for_id("component-NOT-HEX")
            .expect_err("invalid component_id must fail");
        assert!(
            format!("{err:#}").contains("lowercase SHA-256 digest"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn parse_component_repository_base_rejects_missing_package_segments() {
        let err = parse_component_repository_base("oci://ghcr.io/trustmee")
            .expect_err("missing package path must fail");
        assert!(
            format!("{err:#}").contains("<namespace>/<package>"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn parse_cbor_trustmee_eat_accepts_integer_claim_keys() {
        let claims = CborValue::Map(vec![
            (
                CborValue::Integer(Integer::from(TRUSTMEE_CBOR_KEY_EAT_PROFILE)),
                CborValue::Text(TRUSTMEE_EAT_PROFILE.to_string()),
            ),
            (
                CborValue::Integer(Integer::from(TRUSTMEE_CBOR_KEY_COMPONENT_ID)),
                CborValue::Text(
                    "component-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            ),
            (
                CborValue::Integer(Integer::from(TRUSTMEE_CBOR_KEY_EVIDENCE_TYPE)),
                CborValue::Text("application/octet-stream".to_string()),
            ),
            (
                CborValue::Integer(Integer::from(TRUSTMEE_CBOR_KEY_EVIDENCE)),
                CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            ),
        ]);

        let mut bytes = Vec::new();
        ciborium::into_writer(&claims, &mut bytes).expect("serialize CBOR EAT");

        let parsed = parse_cbor_trustmee_eat(&bytes).expect("parse CBOR EAT");
        assert_eq!(
            parsed.component_id,
            "component-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(parsed.evidence_media_type, "application/octet-stream");
        assert_eq!(parsed.evidence, vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
