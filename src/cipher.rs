use libc::size_t;
use std::convert::TryFrom;
use std::io::Cursor;
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use rustls::server::{ClientCertVerifier, UnparsedCertRevocationList, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    Certificate, PrivateKey, RootCertStore, SupportedCipherSuite, ALL_CIPHER_SUITES,
    DEFAULT_CIPHER_SUITES,
};
use rustls_pemfile::{certs, crls, pkcs8_private_keys, rsa_private_keys};

use crate::error::rustls_result;
use crate::rslice::{rustls_slice_bytes, rustls_str};
use crate::rustls_result::AlreadyUsed;
use crate::{
    error, ffi_panic_boundary, try_arc_from_ptr, try_box_from_ptr, try_mut_from_ptr,
    try_ref_from_ptr, try_slice, ArcCastPtr, BoxCastPtr, CastPtr,
};
use rustls_result::NullParameter;

/// An X.509 certificate, as used in rustls.
/// Corresponds to `Certificate` in the Rust API.
/// <https://docs.rs/rustls/latest/rustls/struct.Certificate.html>
pub struct rustls_certificate {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certificate {
    type RustType = Certificate;
}

impl rustls_certificate {
    /// Get the DER data of the certificate itself.
    /// The data is owned by the certificate and has the same lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_certificate_get_der(
        cert: *const rustls_certificate,
        out_der_data: *mut *const u8,
        out_der_len: *mut size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cert = try_ref_from_ptr!(cert);
            if out_der_data.is_null() || out_der_len.is_null() {
                return NullParameter
            }
            let der = cert.as_ref();
            unsafe {
                *out_der_data = der.as_ptr();
                *out_der_len = der.len();
            }
            rustls_result::Ok
        }
    }
}

/// A cipher suite supported by rustls.
pub struct rustls_supported_ciphersuite {
    _private: [u8; 0],
}

impl CastPtr for rustls_supported_ciphersuite {
    type RustType = SupportedCipherSuite;
}

impl rustls_supported_ciphersuite {
    /// Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
    /// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
    /// The bytes from the assignment are interpreted in network order.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuite_get_suite(
        supported_ciphersuite: *const rustls_supported_ciphersuite,
    ) -> u16 {
        let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
        match supported_ciphersuite {
            rustls::SupportedCipherSuite::Tls12(sc) => &sc.common,
            rustls::SupportedCipherSuite::Tls13(sc) => &sc.common,
        }
        .suite
        .get_u16()
    }
}

/// Returns the name of the ciphersuite as a `rustls_str`. If the provided
/// ciphersuite is invalid, the rustls_str will contain the empty string. The
/// lifetime of the `rustls_str` is the lifetime of the program, it does not
/// need to be freed.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuite_get_name(
    supported_ciphersuite: *const rustls_supported_ciphersuite,
) -> rustls_str<'static> {
    let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
    let s = supported_ciphersuite.suite().as_str().unwrap_or("");
    match rustls_str::try_from(s) {
        Ok(s) => s,
        Err(_) => rustls_str::from_str_unchecked(""),
    }
}

/// Return the length of rustls' list of supported cipher suites.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_len() -> usize {
    ALL_CIPHER_SUITES.len()
}

/// Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
/// for i < rustls_all_ciphersuites_len().
/// The returned pointer is valid for the lifetime of the program and may be used directly when
/// building a ClientConfig or ServerConfig.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_get_entry(
    i: size_t,
) -> *const rustls_supported_ciphersuite {
    match ALL_CIPHER_SUITES.get(i) {
        Some(cs) => cs as *const SupportedCipherSuite as *const _,
        None => null(),
    }
}

/// Return the length of rustls' list of default cipher suites.
#[no_mangle]
pub extern "C" fn rustls_default_ciphersuites_len() -> usize {
    DEFAULT_CIPHER_SUITES.len()
}

/// Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
/// for i < rustls_default_ciphersuites_len().
/// The returned pointer is valid for the lifetime of the program and may be used directly when
/// building a ClientConfig or ServerConfig.
#[no_mangle]
pub extern "C" fn rustls_default_ciphersuites_get_entry(
    i: size_t,
) -> *const rustls_supported_ciphersuite {
    match DEFAULT_CIPHER_SUITES.get(i) {
        Some(cs) => cs as *const SupportedCipherSuite as *const _,
        None => null(),
    }
}

/// Rustls' list of supported cipher suites. This is an array of pointers, and
/// its length is given by `RUSTLS_ALL_CIPHER_SUITES_LEN`. The pointers will
/// always be valid. The contents and order of this array may change between
/// releases.
#[no_mangle]
pub static mut RUSTLS_ALL_CIPHER_SUITES: [*const rustls_supported_ciphersuite; 9] = [
    &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
];

/// The length of the array `RUSTLS_ALL_CIPHER_SUITES`.
#[no_mangle]
pub static RUSTLS_ALL_CIPHER_SUITES_LEN: usize = unsafe { RUSTLS_ALL_CIPHER_SUITES.len() };

/// Rustls' list of default cipher suites. This is an array of pointers, and
/// its length is given by `RUSTLS_DEFAULT_CIPHER_SUITES_LEN`. The pointers
/// will always be valid. The contents and order of this array may change
/// between releases.
#[no_mangle]
pub static mut RUSTLS_DEFAULT_CIPHER_SUITES: [*const rustls_supported_ciphersuite; 9] = [
    &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
];

/// The length of the array `RUSTLS_DEFAULT_CIPHER_SUITES`.
#[no_mangle]
pub static RUSTLS_DEFAULT_CIPHER_SUITES_LEN: usize = unsafe { RUSTLS_DEFAULT_CIPHER_SUITES.len() };

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice;
    use std::str;

    #[test]
    fn all_cipher_suites_arrays() {
        assert_eq!(RUSTLS_ALL_CIPHER_SUITES_LEN, ALL_CIPHER_SUITES.len());
        for (original, ffi) in ALL_CIPHER_SUITES
            .iter()
            .zip(unsafe { RUSTLS_ALL_CIPHER_SUITES }.iter().copied())
        {
            let ffi_cipher_suite = try_ref_from_ptr!(ffi);
            assert_eq!(original, ffi_cipher_suite);
        }
    }

    #[test]
    fn default_cipher_suites_arrays() {
        assert_eq!(
            RUSTLS_DEFAULT_CIPHER_SUITES_LEN,
            DEFAULT_CIPHER_SUITES.len()
        );
        for (original, ffi) in DEFAULT_CIPHER_SUITES
            .iter()
            .zip(unsafe { RUSTLS_DEFAULT_CIPHER_SUITES }.iter().copied())
        {
            let ffi_cipher_suite = try_ref_from_ptr!(ffi);
            assert_eq!(original, ffi_cipher_suite);
        }
    }

    #[test]
    fn ciphersuite_get_name() {
        let suite = rustls_all_ciphersuites_get_entry(0);
        let s = rustls_supported_ciphersuite_get_name(suite);
        let want = "TLS13_AES_256_GCM_SHA384";
        unsafe {
            let got = str::from_utf8(slice::from_raw_parts(s.data as *const u8, s.len)).unwrap();
            assert_eq!(want, got)
        }
    }

    #[test]
    fn test_all_ciphersuites_len() {
        let len = rustls_all_ciphersuites_len();
        assert!(len > 2);
    }
}

/// The complete chain of certificates to send during a TLS handshake,
/// plus a private key that matches the end-entity (leaf) certificate.
/// Corresponds to `CertifiedKey` in the Rust API.
/// <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
pub struct rustls_certified_key {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certified_key {
    type RustType = CertifiedKey;
}

impl ArcCastPtr for rustls_certified_key {}

impl rustls_certified_key {
    /// Build a `rustls_certified_key` from a certificate chain and a private key.
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `private_key` must point to a buffer of `private_key_len` bytes, containing
    /// a PEM-encoded private key in either PKCS#1 or PKCS#8 format.
    ///
    /// On success, this writes a pointer to the newly created
    /// `rustls_certified_key` in `certified_key_out`. That pointer must later
    /// be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    /// internally, this is an atomically reference-counted pointer, so even after
    /// the original caller has called `rustls_certified_key_free`, other objects
    /// may retain a pointer to the object. The memory will be freed when all
    /// references are gone.
    ///
    /// This function does not take ownership of any of its input pointers. It
    /// parses the pointed-to data and makes a copy of the result. You may
    /// free the cert_chain and private_key pointers after calling it.
    ///
    /// Typically, you will build a `rustls_certified_key`, use it to create a
    /// `rustls_server_config` (which increments the reference count), and then
    /// immediately call `rustls_certified_key_free`. That leaves the
    /// `rustls_server_config` in possession of the sole reference, so the
    /// `rustls_certified_key`'s memory will automatically be released when
    /// the `rustls_server_config` is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_build(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        private_key: *const u8,
        private_key_len: size_t,
        certified_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let certified_key_out: &mut *const rustls_certified_key = unsafe {
                match certified_key_out.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let certified_key = match rustls_certified_key::certified_key_build(
                cert_chain, cert_chain_len, private_key, private_key_len) {
                Ok(key) => Box::new(key),
                Err(rr) => return rr,
            };
            let certified_key = Arc::into_raw(Arc::new(*certified_key)) as *const _;
            *certified_key_out = certified_key;
            rustls_result::Ok
        }
    }

    /// Return the i-th rustls_certificate in the rustls_certified_key. 0 gives the
    /// end-entity certificate. 1 and higher give certificates from the chain.
    /// Indexes higher than the last available certificate return NULL.
    ///
    /// The returned certificate is valid until the rustls_certified_key is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_get_certificate(
        certified_key: *const rustls_certified_key,
        i: size_t,
    ) -> *const rustls_certificate {
        ffi_panic_boundary! {
            let certified_key: &CertifiedKey = try_ref_from_ptr!(certified_key);
            match certified_key.cert.get(i) {
                Some(cert) => cert as *const Certificate as *const _,
                None => null()
            }
        }
    }

    /// Create a copy of the rustls_certified_key with the given OCSP response data
    /// as DER encoded bytes. The OCSP response may be given as NULL to clear any
    /// possibly present OCSP data from the cloned key.
    /// The cloned key is independent from its original and needs to be freed
    /// by the application.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_clone_with_ocsp(
        certified_key: *const rustls_certified_key,
        ocsp_response: *const rustls_slice_bytes,
        cloned_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cloned_key_out: &mut *const rustls_certified_key = unsafe {
                match cloned_key_out.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let certified_key: &CertifiedKey = try_ref_from_ptr!(certified_key);
            let mut new_key = certified_key.clone();
            if !ocsp_response.is_null() {
                let ocsp_slice = unsafe{ &*ocsp_response };
                new_key.ocsp = Some(Vec::from(try_slice!(ocsp_slice.data, ocsp_slice.len)));
            } else {
                new_key.ocsp = None;
            }
            *cloned_key_out = ArcCastPtr::to_const_ptr(new_key);
            rustls_result::Ok
        }
    }

    /// "Free" a certified_key previously returned from
    /// rustls_certified_key_build. Since certified_key is actually an
    /// atomically reference-counted pointer, extant certified_key may still
    /// hold an internal reference to the Rust object. However, C code must
    /// consider this pointer unusable after "free"ing it.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_free(key: *const rustls_certified_key) {
        ffi_panic_boundary! {
            rustls_certified_key::free(key);
        }
    }

    fn certified_key_build(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        private_key: *const u8,
        private_key_len: size_t,
    ) -> Result<CertifiedKey, rustls_result> {
        let mut cert_chain: &[u8] = unsafe {
            if cert_chain.is_null() {
                return Err(NullParameter);
            }
            slice::from_raw_parts(cert_chain, cert_chain_len)
        };
        let private_key: &[u8] = unsafe {
            if private_key.is_null() {
                return Err(NullParameter);
            }
            slice::from_raw_parts(private_key, private_key_len)
        };
        let mut private_keys: Vec<Vec<u8>> = match pkcs8_private_keys(&mut Cursor::new(private_key))
        {
            Ok(v) => v,
            Err(_) => return Err(rustls_result::PrivateKeyParseError),
        };
        let private_key: PrivateKey = match private_keys.pop() {
            Some(p) => PrivateKey(p),
            None => {
                private_keys = match rsa_private_keys(&mut Cursor::new(private_key)) {
                    Ok(v) => v,
                    Err(_) => return Err(rustls_result::PrivateKeyParseError),
                };
                let rsa_private_key: PrivateKey = match private_keys.pop() {
                    Some(p) => PrivateKey(p),
                    None => return Err(rustls_result::PrivateKeyParseError),
                };
                rsa_private_key
            }
        };
        let signing_key = match rustls::sign::any_supported_type(&private_key) {
            Ok(key) => key,
            Err(_) => return Err(rustls_result::PrivateKeyParseError),
        };
        let parsed_chain: Vec<Certificate> = match certs(&mut cert_chain) {
            Ok(v) => v.into_iter().map(Certificate).collect(),
            Err(_) => return Err(rustls_result::CertificateParseError),
        };

        Ok(rustls::sign::CertifiedKey::new(parsed_chain, signing_key))
    }
}

/// A root certificate store.
/// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
pub struct rustls_root_cert_store {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_root_cert_store {
    type RustType = RootCertStore;
}

impl BoxCastPtr for rustls_root_cert_store {}

impl ArcCastPtr for rustls_root_cert_store {}

impl rustls_root_cert_store {
    /// Create a rustls_root_cert_store. Caller owns the memory and must
    /// eventually call rustls_root_cert_store_free. The store starts out empty.
    /// Caller must add root certificates with rustls_root_cert_store_add_pem.
    /// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html#method.empty>
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_new() -> *mut rustls_root_cert_store {
        ffi_panic_boundary! {
            let store = rustls::RootCertStore::empty();
            BoxCastPtr::to_mut_ptr(store)
        }
    }

    /// Add one or more certificates to the root cert store using PEM encoded data.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_add_pem(
        store: *mut rustls_root_cert_store,
        pem: *const u8,
        pem_len: size_t,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let certs_pem: &[u8] = try_slice!(pem, pem_len);
            let store: &mut RootCertStore = try_mut_from_ptr!(store);

            let certs_der = match rustls_pemfile::certs(&mut Cursor::new(certs_pem)) {
                Ok(vv) => vv,
                Err(_) => return rustls_result::CertificateParseError,
            };
            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut new_store = RootCertStore::empty();
            let (parsed, rejected) = new_store.add_parsable_certificates(&certs_der);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            store.roots.append(&mut new_store.roots);
            rustls_result::Ok
        }
    }

    /// Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_free(store: *mut rustls_root_cert_store) {
        ffi_panic_boundary! {
            let store = try_box_from_ptr!(store);
            drop(store)
        }
    }
}

/// A built client certificate verifier that can be provided to a `rustls_server_config_builder`
/// with `rustls_server_config_builder_set_client_verifier`.
pub struct rustls_client_cert_verifier {
    _private: [u8; 0],
}

impl CastPtr for rustls_client_cert_verifier {
    type RustType = Arc<dyn ClientCertVerifier>;
}

impl BoxCastPtr for rustls_client_cert_verifier {}

impl rustls_client_cert_verifier {
    /// Free a `rustls_client_cert_verifier` previously returned from
    /// `rustls_client_cert_verifier_builder_build`. Calling with NULL is fine. Must not be
    /// called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_free(verifier: *mut rustls_client_cert_verifier) {
        ffi_panic_boundary! {
            BoxCastPtr::to_box(verifier);
        }
    }
}

/// A client certificate verifier being constructed. A builder can be modified by,
/// e.g. `rustls_web_pki_client_cert_verifier_builder_add_crl`. Once you're
/// done configuring settings, call `rustls_web_pki_client_cert_verifier_builder_build`
/// to turn it into a `rustls_client_cert_verifier`. This object is not safe
/// for concurrent mutation.
// TODO(@cpu): Add rustdoc link once available.
pub struct rustls_web_pki_client_cert_verifier_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

pub(crate) struct ClientCertVerifierBuilder {
    roots: Arc<RootCertStore>,
    crls: Vec<UnparsedCertRevocationList>,
    allow_anonymous: bool,
}

impl CastPtr for rustls_web_pki_client_cert_verifier_builder {
    type RustType = Option<ClientCertVerifierBuilder>;
}

impl BoxCastPtr for rustls_web_pki_client_cert_verifier_builder {}

impl rustls_web_pki_client_cert_verifier_builder {
    /// Create a `rustls_web_pki_client_cert_verifier_builder`. Caller owns the memory and must
    /// eventually call `rustls_web_pki_client_cert_verifier_builder_build`, then free the
    /// resulting `rustls_client_cert_verifier`.
    ///
    /// Without further modification the builder will produce a client certificate verifier that
    /// will require a client present a client certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder.
    ///
    /// Anonymous unauthenticated clients will not be permitted unless
    /// `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_client_cert_verifier_builder {
        ffi_panic_boundary! {
            let store: Arc<RootCertStore> = try_arc_from_ptr!(store);
            let builder = ClientCertVerifierBuilder {
                roots: store,
                crls: Vec::default(),
                allow_anonymous: false,
            };
            BoxCastPtr::to_mut_ptr(Some(builder))
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the client certificate verifier
    /// builder by reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_add_crl(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder: &mut Option<ClientCertVerifierBuilder> = try_mut_from_ptr!(builder);

            let crl_pem: &[u8] = try_slice!(crl_pem, crl_pem_len);
            let crls_der: Vec<UnparsedCertRevocationList> = match crls(&mut Cursor::new(crl_pem)) {
                Ok(vv) => vv.into_iter().map(UnparsedCertRevocationList).collect(),
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };

            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.crls.extend(crls_der);

            rustls_result::Ok
        }
    }

    /// Allow unauthenticated anonymous clients in addition to those that present a client
    /// certificate that chains to one of the verifier's configured trust anchors.
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder: &mut Option<ClientCertVerifierBuilder> = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.allow_anonymous = true;

            rustls_result::Ok
        }
    }

    /// Create a new client certificate verifier from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_server_config` instances and must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_web_pki_client_cert_verifier_builder_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_build(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        verifier_out: *mut *mut rustls_client_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder: &mut Option<ClientCertVerifierBuilder> = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder.take() {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            let mut builder = WebPkiClientVerifier::builder(client_verifier_builder.roots)
                .with_crls(client_verifier_builder.crls);
            if client_verifier_builder.allow_anonymous {
                builder = builder.allow_unauthenticated();
            }

            let verifier = match builder.build() {
                Ok(v) => v,
                Err(e) => return error::map_verifier_builder_error(e),
            };
            BoxCastPtr::set_mut_ptr(verifier_out, verifier);

            rustls_result::Ok
        }
    }

    /// Free a `rustls_client_cert_verifier_builder` previously returned from
    /// `rustls_client_cert_verifier_builder_new`. Calling with NULL is fine. Must not be
    /// called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_free(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) {
        ffi_panic_boundary! {
            BoxCastPtr::to_box(builder);
        }
    }
}
