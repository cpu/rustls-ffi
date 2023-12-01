use libc::size_t;
use rustls::SupportedCipherSuite;
use std::sync::Arc;

use crate::cipher::rustls_supported_ciphersuite;
use crate::rustls_result::NullParameter;
use crate::{
    ffi_panic_boundary, free_arc, rustls_result, to_arc_const_ptr, try_clone_arc, Castable,
    OwnershipArc,
};

pub struct rustls_crypto_provider {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

pub(crate) struct CryptoProvider {
    pub(crate) provider: Arc<rustls::crypto::CryptoProvider>,
    pub(crate) ciphersuites: Vec<*const rustls_supported_ciphersuite>,
}

impl Castable for rustls_crypto_provider {
    type Ownership = OwnershipArc;
    type RustType = CryptoProvider;
}

impl rustls_crypto_provider {
    fn provider_cipher_suites(
        provider: &rustls::crypto::CryptoProvider,
    ) -> Vec<*const rustls_supported_ciphersuite> {
        provider
            .cipher_suites
            .iter()
            .map(|cs| cs as *const SupportedCipherSuite as *const _)
            .collect::<Vec<_>>()
    }

    #[cfg(feature = "ring")]
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_ring_new() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let ciphersuites = Self::provider_cipher_suites(&provider);
            to_arc_const_ptr(CryptoProvider {
                provider,
                ciphersuites,
            })
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_aws_lc_rs_new() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let ciphersuites = Self::provider_cipher_suites(&provider);
            to_arc_const_ptr(CryptoProvider {
                provider,
                ciphersuites,
            })
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_cipher_suites(
        provider: *const rustls_crypto_provider,
        cipher_suites: *mut *const *const rustls_supported_ciphersuite,
        cipher_suites_len: *mut size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);

            let cipher_suites: &mut *const *const rustls_supported_ciphersuite = unsafe {
                match cipher_suites.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let cipher_suites_len: &mut size_t = unsafe {
                match cipher_suites_len.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };

            *cipher_suites = provider.ciphersuites.as_ptr();
            *cipher_suites_len = provider.ciphersuites.len();

            rustls_result::Ok
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_free(provider: *const rustls_crypto_provider) {
        ffi_panic_boundary! {
            free_arc(provider);
        }
    }
}

#[cfg(feature = "ring")]
pub(crate) fn default_provider() -> CryptoProvider {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let ciphersuites = rustls_crypto_provider::provider_cipher_suites(&provider);
    CryptoProvider {
        provider,
        ciphersuites,
    }
}

#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
pub(crate) fn default_provider() -> CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let ciphersuites = rustls_crypto_provider::provider_cipher_suites(&provider);
    CryptoProvider {
        provider,
        ciphersuites,
    }
}
