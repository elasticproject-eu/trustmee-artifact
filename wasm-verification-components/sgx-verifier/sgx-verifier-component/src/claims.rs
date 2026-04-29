// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside an SGX Quote and
//! serialize it into a JSON.

use anyhow::*;
use serde_json::{Map, Value};

use crate::TeeEvidenceParsedClaim;

use super::types::*;

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

pub fn generate_parsed_claims(quote: sgx_quote3_t) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    // Claims from SGX Quote Header.
    parse_claim!(quote_header, "version", quote.header.version);
    parse_claim!(quote_header, "att_key_type", quote.header.att_key_type);
    parse_claim!(quote_header, "att_key_data_0", quote.header.att_key_data_0);
    parse_claim!(quote_header, "qe_svn", quote.header.qe_svn);
    parse_claim!(quote_header, "pce_svn", quote.header.pce_svn);
    parse_claim!(quote_header, "vendor_id", quote.header.vendor_id);
    parse_claim!(quote_header, "user_data", quote.header.user_data);

    parse_claim!(quote_body, "cpu_svn", quote.report_body.cpu_svn);
    parse_claim!(quote_body, "misc_select", quote.report_body.misc_select);
    parse_claim!(quote_body, "reserved1", quote.report_body.reserved1);
    parse_claim!(
        quote_body,
        "isv_ext_prod_id",
        quote.report_body.isv_ext_prod_id
    );
    parse_claim!(
        quote_body,
        "attributes.flags",
        quote.report_body.attributes.flags
    );
    parse_claim!(
        quote_body,
        "attributes.xfrm",
        quote.report_body.attributes.xfrm
    );
    parse_claim!(quote_body, "mr_enclave", quote.report_body.mr_enclave);
    parse_claim!(quote_body, "reserved2", quote.report_body.reserved2);
    parse_claim!(quote_body, "mr_signer", quote.report_body.mr_signer);
    parse_claim!(quote_body, "reserved3", quote.report_body.reserved3);
    parse_claim!(quote_body, "config_id", quote.report_body.config_id);
    parse_claim!(quote_body, "isv_prod_id", quote.report_body.isv_prod_id);
    parse_claim!(quote_body, "isv_svn", quote.report_body.isv_svn);
    parse_claim!(quote_body, "config_svn", quote.report_body.config_svn);
    parse_claim!(quote_body, "reserved4", quote.report_body.reserved4);
    parse_claim!(quote_body, "isv_family_id", quote.report_body.isv_family_id);
    parse_claim!(quote_body, "report_data", quote.report_body.report_data);

    let mut claims = Map::new();
    parse_claim!(claims, "header", quote_header);
    parse_claim!(claims, "body", quote_body);
    parse_claim!(claims, "report_data", quote.report_body.report_data);
    parse_claim!(claims, "init_data", quote.report_body.config_id);

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}
