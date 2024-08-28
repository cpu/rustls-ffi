use libc::size_t;
use std::slice;
use std::sync::Arc;

use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::{
    arc_castable, box_castable, ffi_panic_boundary, free_arc, free_box, rustls_result,
    set_arc_mut_ptr, set_boxed_mut_ptr, to_boxed_mut_ptr, try_clone_arc, try_mut_from_ptr,
    try_mut_from_ptr_ptr, try_ref_from_ptr, try_ref_from_ptr_ptr, try_slice, try_take,
};

box_castable! {
    /// A `rustls_crypto_provider` builder.
    pub struct rustls_crypto_provider_builder(Option<CryptoProviderBuilder>);
}

/// A builder for customizing a `CryptoProvider`. Can be used to install a process-wide default.
#[derive(Debug)]
pub struct CryptoProviderBuilder {
    base: Arc<CryptoProvider>,
    cipher_suites: Vec<SupportedCipherSuite>,
}

impl CryptoProviderBuilder {
    fn build_provider(self) -> CryptoProvider {
        let cipher_suites = match self.cipher_suites.is_empty() {
            true => self.base.cipher_suites.clone(),
            false => self.cipher_suites,
        };

        // Unfortunately we can't use the `..` syntax to fill in the rest of the provider
        // fields, because we're working with `Arc<CryptoProvider>` as the base,
        // not `CryptoProvider`.
        // TODO(#450): once MSRV is 1.76+, use `Arc::unwrap_or_clone`.
        CryptoProvider {
            cipher_suites,
            kx_groups: self.base.kx_groups.clone(),
            signature_verification_algorithms: self.base.signature_verification_algorithms,
            secure_random: self.base.secure_random,
            key_provider: self.base.key_provider,
        }
    }
}

/// Constructs a new `rustls_crypto_provider_builder` using the process-wide default crypto
/// provider as the base crypto provider to be customized.
///
/// When this function returns `rustls_result::Ok` a pointer to the `rustls_crypto_provider_builder`
/// is written to `builder_out`. It returns `rustls_result::NoDefaultCryptoProvider` if no default
/// provider has been registered.
///
/// The caller owns the returned `rustls_crypto_provider_builder` and must free it using
/// `rustls_crypto_provider_builder_free`.
///
/// This function is typically used for customizing the default crypto provider for specific
/// connections. For example, a typical workflow might be to:
///
/// * Either:
///   * Use the default `aws-lc-rs` or `*ring*` provider that rustls-ffi is built with based on
///     the `CRYPTO_PROVIDER` build variable.
///   * Call `rustls_crypto_provider_builder_new_with_base` with the desired provider, and
///     then install it as the process default with
///     `rustls_crypto_provider_builder_build_as_default`.
/// * Afterward, as required for customization:
///   * Use `rustls_crypto_provider_builder_new_from_default` to get a builder backed by the
///     default crypto provider.
///   * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
///     ciphersuites.
///   * Use `rustls_crypto_provider_builder_build` to build a customized provider.
///   * Provide that customized provider to client or server configuration builders.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_new_from_default(
    builder_out: *mut *mut rustls_crypto_provider_builder,
) -> rustls_result {
    ffi_panic_boundary! {
        let provider_out = try_mut_from_ptr_ptr!(builder_out);

        let base = match get_default_or_install_from_crate_features() {
            Some(provider) => provider,
            None => return rustls_result::NoDefaultCryptoProvider,
        };

        set_boxed_mut_ptr(
            provider_out,
            Some(CryptoProviderBuilder {
                base,
                cipher_suites: Vec::default(),
            }),
        );

        rustls_result::Ok
    }
}

/// Constructs a new `rustls_crypto_provider_builder` using the given `rustls_crypto_provider`
/// as the base crypto provider to be customized.
///
/// The caller owns the returned `rustls_crypto_provider_builder` and must free it using
/// `rustls_crypto_provider_builder_free`.
///
/// This function can be used for setting the default process wide crypto provider,
/// or for constructing a custom crypto provider for a specific connection. A typical
/// workflow could be to:
///
/// * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
/// * Install the custom provider as the process-wide default with
///   `rustls_crypto_provider_builder_build_as_default`.
///
/// Or, for per-connection customization:
///
/// * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
/// * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
///   ciphersuites.
/// * Use `rustls_crypto_provider_builder_build` to build a customized provider.
/// * Provide that customized provider to client or server configuration builders.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_new_with_base(
    base: *const rustls_crypto_provider,
) -> *mut rustls_crypto_provider_builder {
    ffi_panic_boundary! {
        to_boxed_mut_ptr(Some(CryptoProviderBuilder {
            base: try_clone_arc!(base),
            cipher_suites: Vec::default(),
        }))
    }
}

/// Customize the supported ciphersuites of the `rustls_crypto_provider_builder`. Returns an
/// error if the builder has already been built. Overwrites any previously set ciphersuites.
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

        let cipher_suites = try_slice!(cipher_suites, cipher_suites_len);
        let mut supported_cipher_suites = Vec::new();
        for cs in cipher_suites {
            let cs = *cs;
            let cs = try_ref_from_ptr!(cs);
            supported_cipher_suites.push(*cs);
        }

        builder.cipher_suites = supported_cipher_suites;
        rustls_result::Ok
    }
}

/// Builds a `rustls_crypto_provider` from the builder and returns it. Returns an error if the
/// builder has already been built.
///
/// The `rustls_crypto_provider_builder` builder is consumed and should not be used
/// for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
/// still free the builder after a successful build.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_build(
    builder: *mut rustls_crypto_provider_builder,
    provider_out: *mut *const rustls_crypto_provider,
) -> rustls_result {
    ffi_panic_boundary! {
        let builder = try_mut_from_ptr!(builder);
        set_arc_mut_ptr(
            try_ref_from_ptr_ptr!(provider_out),
            try_take!(builder).build_provider(),
        );
        rustls_result::Ok
    }
}

/// Builds a `rustls_crypto_provider` from the builder and sets it as the
/// process-wide default crypto provider. Afterward, the default provider
/// can be retrieved using `rustls_crypto_provider_default`.
///
/// This can only be done once per process, and will return an error if a
/// default provider has already been set, or if the builder has already been built.
///
/// The `rustls_crypto_provider_builder` builder is consumed and should not be used
/// for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
/// still free the builder after a successful build.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_build_as_default(
    builder: *mut rustls_crypto_provider_builder,
) -> rustls_result {
    let builder = try_mut_from_ptr!(builder);
    match try_take!(builder).build_provider().install_default() {
        Ok(_) => rustls_result::Ok,
        Err(_) => rustls_result::AlreadyUsed,
    }
}

/// Free the `rustls_crypto_provider_builder`. Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_free(
    builder: *mut rustls_crypto_provider_builder,
) {
    ffi_panic_boundary! {
        free_box(builder);
    }
}

/// Return the `rustls_crypto_provider` backed by the `*ring*` cryptography library. The
/// caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
// TODO(@cpu): Add a feature gate when we add support for other crypto providers.
#[no_mangle]
pub extern "C" fn rustls_ring_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(ring::default_provider())) as *const rustls_crypto_provider
    }
}

/// Retrieve a pointer to the process default `rustls_crypto_provider`. This may return `NULL`
/// if no process default provider has been set using `rustls_crypto_provider_builder_build_default`.
///
/// Caller owns the returned `rustls_crypto_provider` and must free it w/ `rustls_crypto_provider_free`.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_default() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        match CryptoProvider::get_default() {
            Some(provider) => Arc::into_raw(provider.clone()) as *const rustls_crypto_provider,
            None => core::ptr::null(),
        }
    }
}

arc_castable! {
    /// A C representation of a Rustls [`CryptoProvider`].
    pub struct rustls_crypto_provider(CryptoProvider);
}

/// Returns the number of ciphersuites the `rustls_crypto_provider` supports.
///
/// You can use this to know the maximum allowed index for use with
/// `rustls_crypto_provider_ciphersuites_get`.
///
/// This function will return 0 if the `provider` is NULL.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_ciphersuites_len(
    provider: *const rustls_crypto_provider,
) -> usize {
    ffi_panic_boundary! {
        try_clone_arc!(provider).cipher_suites.len()
    }
}

/// Retrieve a pointer to a supported ciphersuite of the `rustls_crypto_provider`.
///
/// This function will return NULL if the `provider` is NULL, or if the index is out of bounds
/// with respect to `rustls_crypto_provider_ciphersuites_len`.
///
/// The lifetime of the returned `rustls_supported_ciphersuite` is equal to the lifetime of the
/// `provider` and should not be used after the `provider` is freed.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_ciphersuites_get(
    provider: *const rustls_crypto_provider,
    index: usize,
) -> *const rustls_supported_ciphersuite {
    ffi_panic_boundary! {
        match try_clone_arc!(provider).cipher_suites.get(index) {
            Some(ciphersuite) => ciphersuite as *const SupportedCipherSuite as *const _,
            None => core::ptr::null(),
        }
    }
}

/// Frees the `rustls_crypto_provider`. Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_free(provider: *const rustls_crypto_provider) {
    ffi_panic_boundary! {
        free_arc(provider);
    }
}

/// Returns the number of ciphersuites the default process-wide crypto provider supports.
///
/// You can use this to know the maximum allowed index for use with
/// `rustls_default_crypto_provider_ciphersuites_get`.
///
/// This function will return 0 if no process-wide default `rustls_crypto_provider` is available.
#[no_mangle]
pub extern "C" fn rustls_default_crypto_provider_ciphersuites_len() -> usize {
    ffi_panic_boundary! {
        match get_default_or_install_from_crate_features() {
            Some(provider) => provider.cipher_suites.len(),
            None => return 0,
        }
    }
}

/// Retrieve a pointer to a supported ciphersuite of the default process-wide crypto provider.
///
/// This function will return NULL if the `provider` is NULL, or if the index is out of bounds
/// with respect to `rustls_default_crypto_provider_ciphersuites_len`.
///
/// The lifetime of the returned `rustls_supported_ciphersuite` is static, as the process-wide
/// default provider lives for as long as the process.
#[no_mangle]
pub extern "C" fn rustls_default_crypto_provider_ciphersuites_get(
    index: usize,
) -> *const rustls_supported_ciphersuite {
    ffi_panic_boundary! {
        let default_provider = match get_default_or_install_from_crate_features() {
            Some(provider) => provider,
            None => return core::ptr::null(),
        };
        match default_provider.cipher_suites.get(index) {
            Some(ciphersuite) => ciphersuite as *const SupportedCipherSuite as *const _,
            None => core::ptr::null(),
        }
    }
}

pub(crate) fn get_default_or_install_from_crate_features() -> Option<Arc<CryptoProvider>> {
    // If a process-wide default has already been installed, return it.
    if let Some(provider) = CryptoProvider::get_default() {
        return Some(provider.clone());
    }

    let provider = match provider_from_crate_features() {
        Some(provider) => provider,
        None => return None,
    };

    // Ignore the error resulting from us losing a race to install the default,
    // and accept the outcome.
    let _ = provider.install_default();

    // Safety: we can unwrap safely here knowing we've just set the default, or
    // lost a race to something else setting the default.
    Some(CryptoProvider::get_default().unwrap().clone())
}

fn provider_from_crate_features() -> Option<CryptoProvider> {
    // TODO(XXX): Switch based on crate feature once ring is optional.
    Some(ring::default_provider())
}
