use libc::size_t;
use std::slice;
use std::sync::Arc;

use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::rustls_result::NullParameter;
use crate::{
    ffi_panic_boundary, free_arc, free_box, rustls_result, set_arc_mut_ptr, to_boxed_mut_ptr,
    try_clone_arc, try_mut_from_ptr, try_ref_from_ptr, try_slice, try_take, Castable, OwnershipArc,
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
    cipher_suites: Vec<SupportedCipherSuite>,
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
    #[cfg(feature = "aws_lc_rs")]
    pub extern "C" fn rustls_crypto_provider_builder_aws_lc_rs(
    ) -> *mut rustls_crypto_provider_builder {
        ffi_panic_boundary! {
            to_boxed_mut_ptr(Some(CryptoProviderBuilder::new_with_aws_lc_rs()))
        }
    }

    /// Specify cipher suites in preference
    /// order; the `cipher_suites` parameter must point to an array containing
    /// `len` pointers to `rustls_supported_ciphersuite` previously obtained
    /// from `rustls_all_ciphersuites_get_entry()`, or to a provided array,
    /// RUSTLS_DEFAULT_CIPHER_SUITES or RUSTLS_ALL_CIPHER_SUITES.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_set_cipher_suites(
        builder: *mut rustls_crypto_provider_builder,
        cipher_suites: *const *const rustls_supported_ciphersuite,
        cipher_suites_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let mut builder = try_take!(builder);

            let cipher_suites = try_slice!(cipher_suites, cipher_suites_len).to_vec();
            let mut supported_cipher_suites = Vec::new();
            for cs in cipher_suites {
                let cs = try_ref_from_ptr!(cs);
                supported_cipher_suites.push(*cs);
            }

            builder.cipher_suites = supported_cipher_suites;
            rustls_result::Ok
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
            let provider = builder.build();

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
        let default_provider = Self::default_provider();
        CryptoProviderBuilder {
            cipher_suites: default_provider.cipher_suites.clone(),
            default_provider,
        }
    }

    #[cfg(feature = "ring")]
    pub(crate) fn new_with_ring() -> CryptoProviderBuilder {
        let default_provider = rustls::crypto::ring::default_provider();
        CryptoProviderBuilder {
            cipher_suites: default_provider.cipher_suites.clone(),
            default_provider,
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    pub(crate) fn new_with_aws_lc_rs() -> CryptoProviderBuilder {
        let default_provider = rustls::crypto::aws_lc_rs::default_provider();
        CryptoProviderBuilder {
            cipher_suites: default_provider.cipher_suites.clone(),
            default_provider,
        }
    }

    pub(crate) fn build(self) -> CryptoProvider {
        let cipher_suites = self
            .cipher_suites
            .iter()
            .map(|cs| cs as *const SupportedCipherSuite as *const _)
            .collect::<Vec<_>>();

        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: self.cipher_suites,
            ..self.default_provider
        });

        CryptoProvider {
            provider,
            cipher_suites,
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
    pub(crate) cipher_suites: Vec<*const rustls_supported_ciphersuite>,
}

impl Castable for rustls_crypto_provider {
    type Ownership = OwnershipArc;
    type RustType = CryptoProvider;
}

impl rustls_crypto_provider {
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

            *cipher_suites = provider.cipher_suites.as_ptr();
            *cipher_suites_len = provider.cipher_suites.len();

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
