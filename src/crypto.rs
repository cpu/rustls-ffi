use std::sync::Arc;

use libc::size_t;
use pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::SupportedCipherSuite;

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
    pub(crate) provider: rustls::crypto::CryptoProvider,
}

impl Castable for rustls_crypto_provider {
    type Ownership = OwnershipArc;
    type RustType = CryptoProvider;
}

impl rustls_crypto_provider {
    #[cfg(feature = "ring")]
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_ring_new() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            to_arc_const_ptr(CryptoProvider {
                provider: rustls::crypto::ring::default_provider()
            })
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_aws_lc_rs_new() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            to_arc_const_ptr(CryptoProvider {
                provider: rustls::crypto::aws_lc_rs::default_provider(),
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

            let provider = try_clone_arc!(provider);
            let supported_cipher_suites = &provider.provider.cipher_suites.iter()
                .map(|cs| cs as *const SupportedCipherSuite as *const _)
                .collect::<Vec<_>>();

            *cipher_suites = supported_cipher_suites.as_ptr();
            *cipher_suites_len = supported_cipher_suites.len();

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
    CryptoProvider {
        provider: rustls::crypto::ring::default_provider(),
    }
}
#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
pub(crate) fn default_provider() -> CryptoProvider {
    CryptoProvider {
        provider: rustls::crypto::aws_lc_rs::default_provider(),
    }
}

#[cfg(feature = "ring")]
pub(crate) fn any_supported_signing_key(
    der: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, rustls::crypto::ring::sign::InvalidKeyError> {
    rustls::crypto::ring::sign::any_supported_type(der)
}

#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
pub(crate) fn any_supported_signing_key(
    der: &PrivateKeyDer<'_>,
) -> Result<Arc<dyn SigningKey>, rustls::crypto::aws_lc_rs::sign::InvalidKeyError> {
    rustls::crypto::aws_lc_rs::sign::any_supported_type(der)
}
