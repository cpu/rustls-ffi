use std::slice;
use std::sync::Arc;

use libc::size_t;
use pki_types::pem::PemObject;
use pki_types::PrivateKeyDer;

#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs;
use rustls::crypto::hpke::Hpke;
#[cfg(feature = "ring")]
use rustls::crypto::ring;
use rustls::crypto::CryptoProvider;
use rustls::sign::SigningKey;
use rustls::SupportedCipherSuite;

use crate::cipher::rustls_supported_ciphersuite;
use crate::error::map_error;
use crate::{
    arc_castable, box_castable, ffi_panic_boundary, free_arc, free_box, rustls_result,
    set_arc_mut_ptr, set_boxed_mut_ptr, to_arc_const_ptr, to_boxed_mut_ptr, try_clone_arc,
    try_mut_from_ptr, try_mut_from_ptr_ptr, try_ref_from_ptr, try_ref_from_ptr_ptr, try_slice,
    try_slice_mut, try_take,
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

/// Customize the supported ciphersuites of the `rustls_crypto_provider_builder`.
///
/// Returns an error if the builder has already been built. Overwrites any previously
/// set ciphersuites.
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
/// process-wide default crypto provider.
///
/// Afterward, the default provider can be retrieved using `rustls_crypto_provider_default`.
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

/// Free the `rustls_crypto_provider_builder`.
///
/// Calling with `NULL` is fine.
/// Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_builder_free(
    builder: *mut rustls_crypto_provider_builder,
) {
    ffi_panic_boundary! {
        free_box(builder);
    }
}

/// Return the `rustls_crypto_provider` backed by the `*ring*` cryptography library.
///
/// The caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
#[no_mangle]
#[cfg(feature = "ring")]
pub extern "C" fn rustls_ring_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(ring::default_provider())) as *const rustls_crypto_provider
    }
}

/// Return the `rustls_crypto_provider` backed by the `aws-lc-rs` cryptography library.
///
/// The caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
#[no_mangle]
#[cfg(feature = "aws-lc-rs")]
pub extern "C" fn rustls_aws_lc_rs_crypto_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(aws_lc_rs::default_provider())) as *const rustls_crypto_provider
    }
}

/// Return a `rustls_crypto_provider` that uses FIPS140-3 approved cryptography.
///
/// Using this function expresses in your code that you require FIPS-approved cryptography,
/// and will not compile if you make a mistake with cargo features.
///
/// See the upstream [rustls FIPS documentation][FIPS] for more information.
///
/// The caller owns the returned `rustls_crypto_provider` and must free it using
/// `rustls_crypto_provider_free`.
///
/// [FIPS]: https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html
#[no_mangle]
#[cfg(feature = "fips")]
pub extern "C" fn rustls_default_fips_provider() -> *const rustls_crypto_provider {
    ffi_panic_boundary! {
        Arc::into_raw(Arc::new(rustls::crypto::default_fips_provider()))
            as *const rustls_crypto_provider
        }
}

/// Return the number of supported HPKE suites provided by the `aws-lc-rs` cryptography library.
///
/// This can be used in combination with `rustls_aws_lc_rs_hpke_get` to retrieve supported HPKE
/// suites.
#[no_mangle]
#[cfg(feature = "aws-lc-rs")]
pub extern "C" fn rustls_aws_lc_rs_hpke_len() -> usize {
    ffi_panic_boundary! {
        aws_lc_rs::hpke::ALL_SUPPORTED_SUITES.len()
    }
}

/// Return a pointer to the HPKE suite at the given index provided by the `aws-lc-rs` cryptography
/// library.
///
/// Returns `NULL` if the index is out of bounds. Use `rustls_aws_lc_rs_hpke_len` to
/// determine the maximum index.
///
/// The caller owns the returned `rustls_hpke` and must free it using `rustls_hpke_free`.
#[no_mangle]
#[cfg(feature = "aws-lc-rs")]
pub extern "C" fn rustls_aws_lc_rs_hpke_get(index: usize) -> *mut rustls_hpke {
    ffi_panic_boundary! {
        match aws_lc_rs::hpke::ALL_SUPPORTED_SUITES.get(index) {
            Some(hpke) => to_boxed_mut_ptr(*hpke),
            None => core::ptr::null_mut(),
        }
    }
}

/// Retrieve a pointer to the process default `rustls_crypto_provider`.
///
/// This may return `NULL` if no process default provider has been set using
/// `rustls_crypto_provider_builder_build_default`.
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

/// Load a private key from the provided PEM content using the crypto provider.
///
/// `private_key` must point to a buffer of `private_key_len` bytes, containing
/// a PEM-encoded private key. The exact formats supported will differ based on
/// the crypto provider in use. The default providers support PKCS#1, PKCS#8 or
/// SEC1 formats.
///
/// When this function returns `rustls_result::Ok` a pointer to a `rustls_signing_key`
/// is written to `signing_key_out`. The caller owns the returned `rustls_signing_key`
/// and must free it with `rustls_signing_key_free`.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_load_key(
    provider: *const rustls_crypto_provider,
    private_key: *const u8,
    private_key_len: size_t,
    signing_key_out: *mut *mut rustls_signing_key,
) -> rustls_result {
    ffi_panic_boundary! {
        let provider = try_clone_arc!(provider);
        let private_key_pem = try_slice!(private_key, private_key_len);
        let signing_key_out = try_mut_from_ptr_ptr!(signing_key_out);

        let private_key_der = match PrivateKeyDer::from_pem_slice(private_key_pem) {
            Ok(der) => der,
            Err(_) => return rustls_result::PrivateKeyParseError,
        };

        let private_key = match provider.key_provider.load_private_key(private_key_der) {
            Ok(key) => key,
            Err(e) => return map_error(e),
        };

        set_boxed_mut_ptr(signing_key_out, private_key);
        rustls_result::Ok
    }
}

/// Write `len` bytes of cryptographically secure random data to `buff` using the crypto provider.
///
/// `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
/// of the buffer.
///
/// Returns `RUSTLS_RESULT_OK` on success, or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_random(
    provider: *const rustls_crypto_provider,
    buff: *mut u8,
    len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        match try_clone_arc!(provider)
            .secure_random
            .fill(try_slice_mut!(buff, len))
        {
            Ok(_) => rustls_result::Ok,
            Err(_) => rustls_result::GetRandomFailed,
        }
    }
}

/// Returns true if the `rustls_crypto_provider` is operating in FIPS mode.
///
/// This covers only the cryptographic parts of FIPS approval. There are also
/// TLS protocol-level recommendations made by NIST. You should prefer to call
/// `rustls_client_config_fips` or `rustls_server_config_fips` which take these
/// into account.
#[no_mangle]
pub extern "C" fn rustls_crypto_provider_fips(provider: *const rustls_crypto_provider) -> bool {
    ffi_panic_boundary! {
        try_ref_from_ptr!(provider).fips()
    }
}

/// Frees the `rustls_crypto_provider`.
///
/// Calling with `NULL` is fine.
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

/// Write `len` bytes of cryptographically secure random data to `buff` using the process-wide
/// default crypto provider.
///
/// `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
/// of the buffer.
///
/// Returns `RUSTLS_RESULT_OK` on success, and one of `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER`
/// or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
#[no_mangle]
pub extern "C" fn rustls_default_crypto_provider_random(
    buff: *mut u8,
    len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        match get_default_or_install_from_crate_features() {
            Some(provider) => match provider.secure_random.fill(try_slice_mut!(buff, len)) {
                Ok(_) => rustls_result::Ok,
                Err(_) => rustls_result::GetRandomFailed,
            },
            None => rustls_result::NoDefaultCryptoProvider,
        }
    }
}

box_castable! {
    /// A signing key that can be used to construct a certified key.
    // NOTE: we box cast an arc over the dyn trait per the pattern described
    //   in our docs[0] for dynamically sized types.
    //   [0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_signing_key(Arc<dyn SigningKey>);
}

impl rustls_signing_key {
    /// Frees the `rustls_signing_key`. This is safe to call with a `NULL` argument, but
    /// must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_signing_key_free(signing_key: *mut rustls_signing_key) {
        ffi_panic_boundary! {
            free_box(signing_key);
        }
    }
}

box_castable! {
    /// A Hybrid Public Key Encryption (HPKE) suite implementation.
    ///
    /// This corresponds to the [Hpke] trait in Rustls.
    ///
    /// If you are using the `aws-lc-rs` feature you can retreive supported HPKE
    /// suites using `rustls_aws_lc_rs_hpke_get()` in combination with
    /// `rustls_aws_lc_rs_hpke_len()`.
    ///
    /// [Hpke]: <https://docs.rs/rustls/latest/rustls/crypto/hpke/trait.Hpke.html>
    // Since we can't pass a `&dyn` trait fat pointer across the FFI boundary we box
    // the ref. This gives us a fixed size pointer to pass. We don't need to box an `Arc`
    // in this case because the ref is `'static`.
    pub struct rustls_hpke(&'static dyn Hpke);
}

/// Return the Key Encapsulation Mechanism (`Kem`) type for HPKE operations with the
/// given suite.
///
/// Listed by IANA, as specified in [RFC 9180 Section 7.1]
///
/// [RFC 9180 Section 7.1]: <https://datatracker.ietf.org/doc/html/rfc9180#kemid-values>
#[no_mangle]
pub extern "C" fn rustls_hpke_kem(hpke: *const rustls_hpke) -> u16 {
    ffi_panic_boundary! {
        u16::from(try_ref_from_ptr!(hpke).suite().kem)
    }
}

/// The Key Derivation Function (`Kdf`) type for HPKE operations with the
/// given suite.
///
/// Listed by IANA, as specified in [RFC 9180 Section 7.2]
///
/// [RFC 9180 Section 7.2]: <https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd>
#[no_mangle]
pub extern "C" fn rustls_hpke_kdf(hpke: *const rustls_hpke) -> u16 {
    ffi_panic_boundary! {
        u16::from(try_ref_from_ptr!(hpke).suite().sym.kdf_id)
    }
}

/// The Authenticated Encryption with Associated Data (`Aead`) type for HPKE operations with the
/// given suite.
///
/// Listed by IANA, as specified in [RFC 9180 Section 7.3]
///
/// [RFC 9180 Section 7.3]: <https://datatracker.ietf.org/doc/html/rfc9180#name-authenticated-encryption-wi>
#[no_mangle]
pub extern "C" fn rustls_hpke_aead(hpke: *const rustls_hpke) -> u16 {
    ffi_panic_boundary! {
        u16::from(try_ref_from_ptr!(hpke).suite().sym.aead_id)
    }
}

/// Generate a `rustls_hpke_public_key` suitable for ECH GREASE using the provided `rustls_hpke`.
///
/// A new `rustls_hpke_public_key` is written to `pk_out` when `RUSTLS_RESULT_OK` is returned.
/// The caller owns this `rustls_hpke_public_key` and must call `rustls_hpke_public_key_free`.
/// The lifetime of the `rustls_hpke_public_key` is not tied to the `rustls_hpke` lifetime.
///
/// If an error result is returned `pk_out` is unused.
#[no_mangle]
pub extern "C" fn rustls_hpke_grease_public_key(
    hpke: *const rustls_hpke,
    pk_out: *mut *const rustls_hpke_public_key,
) -> rustls_result {
    ffi_panic_boundary! {
        let suite = try_ref_from_ptr!(hpke);
        let out = try_ref_from_ptr_ptr!(pk_out);

        // Generate a new keypair and throw away the private key.
        // In the future we may want a more capable API but there's nothing for
        // rustls-ffi to do with HPKE private keys at this time.
        let pk = match suite.generate_key_pair() {
            Ok((pk, _)) => pk,
            Err(e) => return map_error(e),
        };
        set_arc_mut_ptr(out, pk.0);

        rustls_result::Ok
    }
}

/// Frees the `rustls_hpke`. This is safe to call with a `NULL` argument, but
/// must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_hpke_free(hpke: *mut rustls_hpke) {
    ffi_panic_boundary! {
        free_box(hpke)
    }
}

arc_castable! {
    /// An HPKE public key, suitable for use for ECH GREASE.
    ///
    /// An instance can be obtained from a `rustls_hpke` using `rustls_hpke_grease_public_key`,
    /// or read from an existing DER encoded data using `rustls_hpke_public_key_load`.
    ///
    /// Instances must eventually be freed with `rustls_hpke_public_key_free`.
    pub struct rustls_hpke_public_key(Vec<u8>);
}

/// Retrieve the DER encoded public key from the `rustls_hpke_public_key`.
///
/// Writes a pointer to the public key to `pk_out` and the length of the public key to `pk_out_len`
/// when the function returns `RUSTLS_RESULT_OK`. The `rustls_hpke_public_key` is not modified
/// and owns the returned data. The caller **must not** maintain a reference to the data after
/// the `rustls_hpke_public_key` is freed.
///
/// If an error result is returned (for example because a parameter was NULL) the out parameters
/// are untouched.
#[no_mangle]
pub extern "C" fn rustls_hpke_public_key_der(
    pk: *const rustls_hpke_public_key,
    pk_out: *mut *const u8,
    pk_out_len: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let pk = try_ref_from_ptr!(pk);

        // We can't use our macros here: u8 and size_t aren't Castable.
        if pk_out.is_null() || pk_out_len.is_null() {
            return rustls_result::NullParameter;
        }

        unsafe {
            *pk_out = pk.as_ptr();
            *pk_out_len = pk.len();
        }

        rustls_result::Ok
    }
}

/// Construct a `rustls_hpke_public_key` from existing DER input.
///
/// The caller owns the returned `rustls_hpke_public_key` and must free it with
/// `rustls_hpke_public_key_free`. The ownership of `public_key_der` remains with
/// the caller.
///
/// Returns NULL if `public_key_der` is NULL.
#[no_mangle]
pub extern "C" fn rustls_hpke_public_key_load(
    public_key_der: *const u8,
    public_key_der_size: size_t,
) -> *const rustls_hpke_public_key {
    ffi_panic_boundary! {
        to_arc_const_ptr(try_slice!(public_key_der, public_key_der_size).to_vec())
    }
}

/// Frees the `rustls_hpke_public_key`. This is safe to call with a `NULL` argument, but
/// must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_hpke_public_key_free(pk: *const rustls_hpke_public_key) {
    ffi_panic_boundary! {
        free_arc(pk)
    }
}

pub(crate) fn get_default_or_install_from_crate_features() -> Option<Arc<CryptoProvider>> {
    // If a process-wide default has already been installed, return it.
    if let Some(provider) = CryptoProvider::get_default() {
        return Some(provider.clone());
    }

    // Ignore the error resulting from us losing a race to install the default,
    // and accept the outcome.
    let _ = provider_from_crate_features()?.install_default();

    // Safety: we can unwrap safely here knowing we've just set the default, or
    // lost a race to something else setting the default.
    Some(CryptoProvider::get_default().unwrap().clone())
}

fn provider_from_crate_features() -> Option<CryptoProvider> {
    // Provider default is unambiguously aws-lc-rs
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    {
        return Some(aws_lc_rs::default_provider());
    }

    // Provider default is unambiguously ring
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    {
        return Some(ring::default_provider());
    }

    // Both features activated - no clear default provider based on
    // crate features.
    #[allow(unreachable_code)]
    None
}

#[cfg(all(test, not(miri)))]
mod tests {
    use std::ptr;

    use super::*;
    use rustls_result;

    /// Simple smoketest of CSRNG fill with specific provider.
    #[test]
    fn random_data() {
        let provider = rustls_crypto_provider_default();
        assert!(!provider.is_null());

        // NULL buffer should return an error.
        let result = rustls_crypto_provider_random(provider, ptr::null_mut(), 1337);
        assert_eq!(result, rustls_result::NullParameter);

        let mut buff = vec![0; 32];

        // NULL provider should return an error and not touch buff.
        let result = rustls_crypto_provider_random(ptr::null(), buff.as_mut_ptr(), buff.len());
        assert_eq!(buff, vec![0; 32]);
        assert_eq!(result, rustls_result::NullParameter);

        // Proper parameters should return OK and overwrite the buffer.
        let result = rustls_crypto_provider_random(provider, buff.as_mut_ptr(), buff.len());
        assert_eq!(result, rustls_result::Ok);
        assert_ne!(buff, vec![0; 32]);
    }

    /// Simple smoketest of CSRNG fill with default provider.
    #[test]
    fn default_random_data() {
        // NULL buffer should return an error.
        let result = rustls_default_crypto_provider_random(ptr::null_mut(), 1337);
        assert_eq!(result, rustls_result::NullParameter);

        let mut buff = vec![0; 32];

        // Proper parameters should return OK and overwrite the buffer.
        let result = rustls_default_crypto_provider_random(buff.as_mut_ptr(), buff.len());
        assert_eq!(result, rustls_result::Ok);
        assert_ne!(buff, vec![0; 32]);
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn test_aws_lc_rs_hpke_suites() {
        let hpke_len = rustls_aws_lc_rs_hpke_len();
        assert!(hpke_len > 0);

        let all_suites = aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
        for (i, rustls_suite) in all_suites.iter().enumerate().take(hpke_len) {
            let ffi_suite = rustls_aws_lc_rs_hpke_get(i);
            assert!(!ffi_suite.is_null());

            assert_eq!(
                rustls_hpke_kem(ffi_suite),
                u16::from(rustls_suite.suite().kem)
            );
            assert_eq!(
                rustls_hpke_kdf(ffi_suite),
                u16::from(rustls_suite.suite().sym.kdf_id)
            );
            assert_eq!(
                rustls_hpke_aead(ffi_suite),
                u16::from(rustls_suite.suite().sym.aead_id)
            );

            // Giving a bad index should result in NULL.
            let bad_ffi_suite = rustls_aws_lc_rs_hpke_get(hpke_len + 1);
            assert!(bad_ffi_suite.is_null());

            // Trying to generate a GREASE public key with a NULL suite should return an error
            // and leave the out ptr NULL.
            let mut pubkey = ptr::null();
            let res = rustls_hpke_grease_public_key(ptr::null(), &mut pubkey);
            assert_eq!(res, rustls_result::NullParameter);
            assert!(pubkey.is_null());

            // Similar for using a null out param.
            let res = rustls_hpke_grease_public_key(ffi_suite, ptr::null_mut());
            assert_eq!(res, rustls_result::NullParameter);

            // We should be able to generate a real pubkey.
            let res = rustls_hpke_grease_public_key(ffi_suite, &mut pubkey);
            assert_eq!(res, rustls_result::Ok);

            // Giving null parameters to rustls_hpke_public_key_der should fail.
            let mut der_out = ptr::null();
            let mut der_out_len = 0;
            let res = rustls_hpke_public_key_der(ptr::null(), &mut der_out, &mut der_out_len);
            assert_eq!(res, rustls_result::NullParameter);
            assert!(der_out.is_null());
            assert_eq!(der_out_len, 0);
            let res = rustls_hpke_public_key_der(pubkey, ptr::null_mut(), &mut der_out_len);
            assert_eq!(res, rustls_result::NullParameter);
            assert_eq!(der_out_len, 0);
            let res = rustls_hpke_public_key_der(pubkey, &mut der_out, ptr::null_mut());
            assert_eq!(res, rustls_result::NullParameter);
            assert!(der_out.is_null());

            // Giving valid parameters should work fine.
            let res = rustls_hpke_public_key_der(pubkey, &mut der_out, &mut der_out_len);
            assert_eq!(res, rustls_result::Ok);
            assert!(!der_out.is_null());
            assert!(der_out_len > 0);

            // Giving a null parameter to rustls_hpke_public_key_load should return NULL.
            let new_pubkey = rustls_hpke_public_key_load(ptr::null(), 0);
            assert!(new_pubkey.is_null());

            // We should be able to load a new public key instance from the DER.
            let new_pubkey = rustls_hpke_public_key_load(der_out, der_out_len);
            assert!(!new_pubkey.is_null());

            rustls_hpke_public_key_free(new_pubkey);
            rustls_hpke_public_key_free(pubkey);
            rustls_hpke_free(ffi_suite);
        }
    }
}
