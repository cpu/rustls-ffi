//! A simple test that updates the `defo.ie.ech.config.der` test file with the ECH
//! config for `defo.ie`, fetched with DNS-over-HTTPS.
//!
//! The client binary can use this file to configure ECH for `defo.ie` as a smoke-test.
use std::fs::File;
use std::io::Write;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;

use rustls::pki_types::EchConfigListBytes;

#[test]
pub fn fetch_test_ech_config() {
    let resolver = Resolver::new(ResolverConfig::google_https(), ResolverOpts::default()).unwrap();
    let encoded_list = lookup_ech(&resolver, "research.cloudflare.com");

    let mut encoded_list_file =
        File::create("tests/research.cloudflare.com.ech.configs.der").unwrap();
    encoded_list_file.write_all(&encoded_list).unwrap();
}

fn lookup_ech(resolver: &Resolver, domain: &str) -> EchConfigListBytes<'static> {
    resolver
        .lookup(domain, RecordType::HTTPS)
        .expect("failed to lookup HTTPS record type")
        .record_iter()
        .find_map(|r| match r.data() {
            RData::HTTPS(svcb) => svcb.svc_params().iter().find_map(|sp| match sp {
                (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => Some(e.clone().0),
                _ => None,
            }),
            _ => None,
        })
        .expect("missing expected HTTPS SvcParam EchConfig record")
        .into()
}
