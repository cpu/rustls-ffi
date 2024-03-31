use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::{env, fs, path::PathBuf};

use serde::Deserialize;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let include_dir = out_dir.join("include");

    fs::create_dir_all(&include_dir).unwrap();
    fs::copy("src/rustls.h", include_dir.join("rustls.h")).unwrap();

    println!("cargo:include={}", include_dir.to_str().unwrap());

    let dest_path = out_dir.join("version.rs");
    let mut f = File::create(dest_path).expect("Could not create file");
    let pkg_version = env!("CARGO_PKG_VERSION");
    writeln!(
        &mut f,
        r#"const RUSTLS_FFI_VERSION: &str = "rustls-ffi/{}/rustls/{}";"#,
        pkg_version,
        rustls_crate_version()
    )
    .expect("Could not write file");

    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
}

fn rustls_crate_version() -> String {
    #[derive(Deserialize)]
    struct CargoToml {
        dependencies: HashMap<String, DependencyValue>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DependencyValue {
        String(String),
        Object { version: String },
    }

    let cargo_toml: CargoToml = toml::from_str(include_str!("Cargo.toml")).unwrap();
    match &cargo_toml.dependencies["rustls"] {
        DependencyValue::String(version) => version,
        DependencyValue::Object { version, .. } => version,
    }
    .clone()
}
