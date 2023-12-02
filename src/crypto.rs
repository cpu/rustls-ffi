use libc::size_t;
use std::sync::Arc;

use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::rustls_result::NullParameter;
use crate::{
    ffi_panic_boundary, free_arc, free_box, rustls_result, set_arc_mut_ptr, to_arc_const_ptr,
    to_boxed_mut_ptr, try_clone_arc, try_mut_from_ptr, try_take, Castable, OwnershipArc,
    OwnershipBox,
};

pub struct rustls_crypto_provider_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl Castable for rustls_crypto_provider_builder {
    type Ownership = OwnershipBox;
    type RustType = Option<CryptoProviderBuilder>;
}

pub(crate) struct CryptoProviderBuilder {
    default_provider: rustls::crypto::CryptoProvider,
    ciphersuites: Vec<SupportedCipherSuite>,
}

impl CryptoProviderBuilder {
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_new() -> *mut rustls_crypto_provider_builder {
        ffi_panic_boundary! {
            to_boxed_mut_ptr(Some(CryptoProviderBuilder::new()))
        }
    }

    #[no_mangle]
    #[cfg(feature = "ring")]
    pub extern "C" fn rustls_crypto_provider_builder_ring() -> *mut rustls_crypto_provider_builder {
        ffi_panic_boundary! {
            to_boxed_mut_ptr(Some(CryptoProviderBuilder::new_with_ring()))
        }
    }

    #[no_mangle]
    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    pub extern "C" fn rustls_crypto_provider_builder_aws_lc_rs(
    ) -> *mut rustls_crypto_provider_builder {
        ffi_panic_boundary! {
            to_boxed_mut_ptr(Some(CryptoProviderBuilder::new_with_aws_lc_rs()))
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_build(
        builder: *mut rustls_crypto_provider_builder,
        provider_out: *mut *const rustls_crypto_provider,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = try_take!(builder);

            let provider = Arc::new(rustls::crypto::CryptoProvider{
                ..builder.default_provider
            });
            let ciphersuites = rustls_crypto_provider::provider_cipher_suites(&provider);
            let provider = CryptoProvider{
                provider,
                ciphersuites
            };

            set_arc_mut_ptr(provider_out, provider);
            rustls_result::Ok
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_free(
        builder: *mut rustls_crypto_provider_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }

    pub(crate) fn new() -> CryptoProviderBuilder {
        CryptoProviderBuilder {
            default_provider: Self::default_provider(),
            ciphersuites: Vec::new(),
        }
    }

    #[cfg(feature = "ring")]
    pub(crate) fn new_with_ring() -> CryptoProviderBuilder {
        CryptoProviderBuilder {
            default_provider: rustls::crypto::ring::default_provider(),
            ciphersuites: Vec::new(),
        }
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    pub(crate) fn new_with_aws_lc_rs() -> CryptoProviderBuilder {
        CryptoProviderBuilder {
            default_provider: rustls::crypto::aws_lc_rs::default_provider(),
            ciphersuites: Vec::new(),
        }
    }

    pub(crate) fn build(self) -> CryptoProvider {
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            ..self.default_provider
        });
        let ciphersuites = rustls_crypto_provider::provider_cipher_suites(&provider);
        CryptoProvider {
            provider,
            ciphersuites,
        }
    }

    #[cfg(feature = "ring")]
    fn default_provider() -> rustls::crypto::CryptoProvider {
        rustls::crypto::ring::default_provider()
    }

    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    fn default_provider() -> rustls::crypto::CryptoProvider {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

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

pub(crate) fn default_provider() -> CryptoProvider {
    CryptoProviderBuilder::new().build()
}
