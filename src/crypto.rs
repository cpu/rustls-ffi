use libc::size_t;
use std::slice;
use std::sync::Arc;

use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::rustls_result::{AlreadyUsed, NullParameter};
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

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_set_cipher_suites(
        builder: *mut rustls_crypto_provider_builder,
        cipher_suites: *const *const rustls_supported_ciphersuite,
        cipher_suites_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

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

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use crate::cipher::{
        rustls_supported_ciphersuite_get_name, rustls_supported_ciphersuite_get_suite,
    };

    use super::*;

    macro_rules! rustls_ok {
        ($result:expr, $custom_msg:expr) => {
            assert_eq!($result, rustls_result::Ok, $custom_msg);
        };
    }

    macro_rules! uninitialized_mut_ptr {
        ($($name:ident),*) => {
            $(
                let mut $name = MaybeUninit::uninit();
                let $name = $name.as_mut_ptr();
            )*
        };
    }

    fn test_provider_ciphersuites(
        provider_builder: *mut rustls_crypto_provider_builder,
        rust_provider: Arc<rustls::crypto::CryptoProvider>,
    ) {
        uninitialized_mut_ptr!(provider);
        let result =
            CryptoProviderBuilder::rustls_crypto_provider_builder_build(provider_builder, provider);
        rustls_ok!(result, "failed to build crypto provider");
        assert!(!provider.is_null());

        uninitialized_mut_ptr!(ciphersuites, ciphersuites_len);
        let result = unsafe {
            rustls_crypto_provider::rustls_crypto_provider_cipher_suites(
                *provider,
                ciphersuites,
                ciphersuites_len,
            )
        };
        rustls_ok!(result, "failed to get ciphersuites from crypto provider");
        assert!(!ciphersuites.is_null());
        assert!(!ciphersuites_len.is_null());

        let ciphersuites = unsafe { slice::from_raw_parts(*ciphersuites, *ciphersuites_len) };
        assert!(!ciphersuites.is_empty());

        let mut ffi_ciphersuites = Vec::new();
        for cs in ciphersuites {
            let suite = rustls_supported_ciphersuite_get_suite(*cs);
            let name = unsafe {
                rustls_supported_ciphersuite_get_name(*cs)
                    .to_str()
                    .to_string()
            };
            ffi_ciphersuites.push((suite, name));
        }

        let rust_ciphersuites = rust_provider
            .cipher_suites
            .iter()
            .map(|cs| {
                (
                    cs.suite().get_u16(),
                    cs.suite().as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(rust_ciphersuites, ffi_ciphersuites);
    }

    #[test]
    fn test_default_provider_ciphersuites() {
        let provider_builder = CryptoProviderBuilder::rustls_crypto_provider_builder_new();
        test_provider_ciphersuites(provider_builder, default_provider().provider);
    }

    #[cfg(feature = "ring")]
    #[test]
    fn test_ring_provider_ciphersuites() {
        let provider_builder = CryptoProviderBuilder::rustls_crypto_provider_builder_ring();
        test_provider_ciphersuites(
            provider_builder,
            rustls::crypto::ring::default_provider().into(),
        );
    }

    #[cfg(feature = "aws_lc_rs")]
    #[test]
    fn test_aws_lc_rs_provider_ciphersuites() {
        let provider_builder = CryptoProviderBuilder::rustls_crypto_provider_builder_aws_lc_rs();
        test_provider_ciphersuites(
            provider_builder,
            rustls::crypto::aws_lc_rs::default_provider().into(),
        );
    }

    #[cfg(all(feature = "aws_lc_rs", feature = "ring"))]
    #[test]
    fn test_ciphersuite_mix_and_match() {
        let aws_provider_builder =
            CryptoProviderBuilder::rustls_crypto_provider_builder_aws_lc_rs();
        uninitialized_mut_ptr!(aws_provider);
        let result = CryptoProviderBuilder::rustls_crypto_provider_builder_build(
            aws_provider_builder,
            aws_provider,
        );
        rustls_ok!(result, "failed to build aws crypto provider");
        assert!(!aws_provider.is_null());

        uninitialized_mut_ptr!(aws_ciphersuites, aws_ciphersuites_len);
        let result = unsafe {
            rustls_crypto_provider::rustls_crypto_provider_cipher_suites(
                *aws_provider,
                aws_ciphersuites,
                aws_ciphersuites_len,
            )
        };
        rustls_ok!(result, "failed to get ciphersuites from crypto provider");
        assert!(!aws_ciphersuites.is_null());
        assert!(!aws_ciphersuites_len.is_null());

        let ciphersuites =
            unsafe { slice::from_raw_parts(*aws_ciphersuites, *aws_ciphersuites_len) };
        assert!(!ciphersuites.is_empty());

        let custom_ciphersuites = ciphersuites
            .into_iter()
            .filter_map(|cs| {
                match unsafe { rustls_supported_ciphersuite_get_name(*cs).to_str() }
                    .starts_with("TLS13")
                {
                    true => Some(*cs),
                    false => None,
                }
            })
            .collect::<Vec<_>>();

        let custom_provider_builder = CryptoProviderBuilder::rustls_crypto_provider_builder_ring();
        uninitialized_mut_ptr!(custom_provider);

        let result = CryptoProviderBuilder::rustls_crypto_provider_builder_set_cipher_suites(
            custom_provider_builder,
            custom_ciphersuites.as_ptr(),
            custom_ciphersuites.len(),
        );
        rustls_ok!(
            result,
            "failed to set ciphersuites on custom crypto provider builder"
        );
        let result = CryptoProviderBuilder::rustls_crypto_provider_builder_build(
            custom_provider_builder,
            custom_provider,
        );
        rustls_ok!(result, "failed to build custom crypto provider");
        assert!(!custom_provider.is_null());

        let custom_provider = unsafe { *custom_provider };
        let custom_provider = try_clone_arc!(custom_provider);
        assert_eq!(
            custom_provider.provider.cipher_suites.len(),
            custom_ciphersuites.len()
        );
        assert_eq!(
            custom_provider.cipher_suites.len(),
            custom_ciphersuites.len()
        );
        assert!(custom_provider.provider.cipher_suites.iter().all(|cs| cs
            .suite()
            .as_str()
            .unwrap()
            .starts_with("TLS13")));
    }
}
