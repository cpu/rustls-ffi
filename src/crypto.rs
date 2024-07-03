use libc::size_t;
use std::io::Cursor;
use std::slice;
use std::sync::Arc;

#[cfg(feature = "ring")]
use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::sign::SigningKey;
use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::error::map_error;
use crate::{
    arc_castable, box_castable, ffi_panic_boundary, free_arc, free_box, rustls_result,
    set_arc_mut_ptr, set_boxed_mut_ptr, try_clone_arc, try_mut_from_ptr, try_mut_from_ptr_ptr,
    try_ref_from_ptr, try_ref_from_ptr_ptr, try_slice, try_take,
};

#[cfg(feature = "ring")]
#[no_mangle]
pub extern "C" fn rustls_ring_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(ring::default_provider())) as *const rustls_crypto_provider
    }
}

box_castable! {
    /// A `rustls_crypto_provider` builder.
    pub struct rustls_crypto_provider_builder(Option<CryptoProviderBuilder>);
}

#[derive(Debug)]
pub struct CryptoProviderBuilder {
    base: Arc<CryptoProvider>,
    cipher_suites: Vec<SupportedCipherSuite>,
}

impl CryptoProviderBuilder {
    /// TODO(XXX): docs
    /// Creates a provider builder using the default crypto provider as the base.
    /// Returns `rustls_result::NoDefaultCryptoProvider` if no default provider has been registered.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_new(
        builder_out: *mut *mut rustls_crypto_provider_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let provider_out = try_mut_from_ptr_ptr!(builder_out);

            let default_provider = match CryptoProvider::get_default() {
                Some(provider) => provider,
                None => return rustls_result::NoDefaultCryptoProvider,
            };

            set_boxed_mut_ptr(
                provider_out,
                Some(Self {
                    base: default_provider.clone(),
                    cipher_suites: Vec::default(),
                }),
            );

            rustls_result::Ok
        }
    }

    /// TODO(XXX): docs
    /// Creates a provider builder using specified crypto provider as the base.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_new_with_base(
        base: *const rustls_crypto_provider,
        builder_out: *mut *mut rustls_crypto_provider_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let base = try_clone_arc!(base);
            let provider_out = try_mut_from_ptr_ptr!(builder_out);

            set_boxed_mut_ptr(
                provider_out,
                Some(Self {
                    base,
                    cipher_suites: Vec::default(),
                }),
            );

            rustls_result::Ok
        }
    }

    /// TODO(XXX): docs
    /// Sets the cipher suites for the provider builder.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_set_cipher_suites(
        builder: *mut rustls_crypto_provider_builder,
        cipher_suites: *const *const rustls_supported_ciphersuite,
        cipher_suites_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                Some(builder) => builder,
                None => return rustls_result::AlreadyUsed,
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

    /// TODO(XXX): Docs
    /// Builds a crypto provider from the builder. The builder is consumed.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_build(
        builder: *mut rustls_crypto_provider_builder,
        provider_out: *mut *const rustls_crypto_provider,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = try_take!(builder);
            let provider_out = try_ref_from_ptr_ptr!(provider_out);

            let cipher_suites = match builder.cipher_suites.is_empty() {
                true => builder.base.cipher_suites.clone(),
                false => builder.cipher_suites,
            };

            // Unfortunately we can't use the `..` syntax to fill in the rest of the provider
            // fields, because we're working with `Arc<CryptoProvider>` as the base,
            // not `CryptoProvider`.
            let provider = CryptoProvider {
                cipher_suites,
                kx_groups: builder.base.kx_groups.clone(),
                signature_verification_algorithms: builder.base.signature_verification_algorithms,
                secure_random: builder.base.secure_random,
                key_provider: builder.base.key_provider,
            };

            set_arc_mut_ptr(provider_out, provider);
            rustls_result::Ok
        }
    }

    /// TODO(XXX): Docs
    /// Builds a crypto provider from the builder and sets it as the default.
    /// The builder is consumed. This can only be done once per process.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_build_default(
        builder: *mut rustls_crypto_provider_builder,
    ) -> rustls_result {
        // TODO(XXX): dedupe w/ the other build fn.

        let builder = try_mut_from_ptr!(builder);
        let builder = try_take!(builder);

        let cipher_suites = match builder.cipher_suites.is_empty() {
            true => builder.base.cipher_suites.clone(),
            false => builder.cipher_suites,
        };

        // Unfortunately we can't use the `..` syntax to fill in the rest of the provider
        // fields, because we're working with `Arc<CryptoProvider>` as the base,
        // not `CryptoProvider`.
        let provider = CryptoProvider {
            cipher_suites,
            kx_groups: builder.base.kx_groups.clone(),
            signature_verification_algorithms: builder.base.signature_verification_algorithms,
            secure_random: builder.base.secure_random,
            key_provider: builder.base.key_provider,
        };

        match provider.install_default() {
            Ok(_) => rustls_result::Ok,
            Err(_) => rustls_result::General, // XXX: more specific error?
        }
    }

    /// TODO(XXX): docs.
    /// Free the builder. Safe to call with NULL, or multiple times.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_builder_free(
        builder: *mut rustls_crypto_provider_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

arc_castable! {
    /// A [`CryptoProvider`].
    pub struct rustls_crypto_provider(CryptoProvider);
}

impl rustls_crypto_provider {
    /// TODO(XXX): docs.
    /// Caller owns `rustls_crypto_provider` and must free w/ `rustls_crypto_provider_free`
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_default() -> *const rustls_crypto_provider {
        ffi_panic_boundary! {
            match CryptoProvider::get_default() {
                Some(provider) => Arc::into_raw(provider.clone()) as *const rustls_crypto_provider,
                None => core::ptr::null(),
            }
        }
    }

    /// TODO(XXX): docs.
    /// Caller owns `rustls_supported_ciphersuites` and must free w/ `rustls_supported_ciphersuites_free`
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_ciphersuites(
        provider: *const rustls_crypto_provider,
        ciphersuites: *mut *const rustls_supported_ciphersuites,
    ) -> rustls_result {
        ffi_panic_boundary! {
            set_arc_mut_ptr(
                try_ref_from_ptr_ptr!(ciphersuites),
                try_clone_arc!(provider).cipher_suites.clone(),
            );
            rustls_result::Ok
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_load_key(
        provider: *const rustls_crypto_provider,
        private_key: *const u8,
        private_key_len: size_t,
        signing_key: *mut *mut rustls_signing_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let private_key_pem = try_slice!(private_key, private_key_len);
            let signing_key_out = try_mut_from_ptr_ptr!(signing_key);

            let private_key_der =
                match rustls_pemfile::private_key(&mut Cursor::new(private_key_pem)) {
                    Ok(Some(p)) => p,
                    _ => return rustls_result::PrivateKeyParseError,
                };

            let private_key = match provider.key_provider.load_private_key(private_key_der) {
                Ok(key) => key,
                Err(e) => return map_error(e),
            };

            set_boxed_mut_ptr(signing_key_out, private_key);
            rustls_result::Ok
        }
    }

    /// TODO(XXX): docs.
    #[no_mangle]
    pub extern "C" fn rustls_crypto_provider_free(provider: *const rustls_crypto_provider) {
        ffi_panic_boundary! {
            free_arc(provider);
        }
    }
}

arc_castable! {
    /// A collection of `rustls_supported_ciphersuite` supported by a `rustls_crypto_provider`
    pub struct rustls_supported_ciphersuites(Vec<SupportedCipherSuite>);
}

impl rustls_supported_ciphersuites {
    /// Returns the number of supported ciphersuites in the collection.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuites_len(
        ciphersuites: *const rustls_supported_ciphersuites,
    ) -> usize {
        ffi_panic_boundary! {
            try_clone_arc!(ciphersuites).len()
        }
    }

    /// Returns the `rustls_supported_ciphersuite` at the given index in the collection.
    ///
    /// Returns `NULL` for out of bounds access.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuites_get(
        ciphersuites: *const rustls_supported_ciphersuites,
        index: usize,
    ) -> *const rustls_supported_ciphersuite {
        ffi_panic_boundary! {
            match try_clone_arc!(ciphersuites).get(index) {
                Some(ciphersuite) => ciphersuite as *const SupportedCipherSuite as *const _,
                None => core::ptr::null(),
            }
        }
    }

    /// Frees the `rustls_supported_ciphersuites` collection. This is safe to call with `NULL`,
    /// or multiple times.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuites_free(
        ciphersuites: *const rustls_supported_ciphersuites,
    ) {
        ffi_panic_boundary! {
            free_arc(ciphersuites);
        }
    }
}

box_castable! {
    /// A signing key that can be used to construct a certified key.
    // Note(XXX): we box cast an arc over the dyn trait per the pattern described
    //   in our docs[0] for dynamically sized types.
    //   [0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_signing_key(Arc<dyn SigningKey>);
}

impl rustls_signing_key {
    /// Frees the `rustls_signing_key`. This is safe to call with `NULL`.
    #[no_mangle]
    pub extern "C" fn rustls_signing_key_free(signing_key: *mut rustls_signing_key) {
        ffi_panic_boundary! {
            free_box(signing_key);
        }
    }
}
