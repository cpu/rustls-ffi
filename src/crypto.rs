use std::sync::Arc;

use pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;

use crate::{ffi_panic_boundary, free_arc, to_arc_const_ptr, Castable, OwnershipArc};

pub struct rustls_crypto_provider {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

pub(crate) struct CryptoProvider {
    pub(crate) provider: &'static dyn rustls::crypto::CryptoProvider,
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
                provider: rustls::crypto::ring::RING,
            })
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_aws_lc_rs_new() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            to_arc_const_ptr(CryptoProvider {
                provider: rustls::crypto::aws_lc_rs::AWS_LC_RS,
            })
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
pub(crate) static DEFAULT_CRYPTO_PROVIDER: CryptoProvider = CryptoProvider {
    provider: rustls::crypto::ring::RING,
};
#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
pub(crate) static DEFAULT_CRYPTO_PROVIDER: CryptoProvider = CryptoProvider {
    provider: rustls::crypto::aws_lc_rs::AWS_LC_RS,
};

#[cfg(feature = "ring")]
pub(crate) static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] =
    rustls::crypto::ring::ALL_CIPHER_SUITES;
#[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
pub(crate) static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] =
    rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES;

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
