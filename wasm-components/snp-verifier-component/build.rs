use std::{env, fs, path::PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap_or_default();

    if target == "wasm32-wasip1" {
        if let Some(lib_dir) = find_wasi_sysroot_libdir(&target) {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        } else {
            println!(
                "cargo:warning=Unable to locate WASI sysroot lib dir for {target}; \
                 set WASI_SDK_PATH to your wasi-sdk install to resolve wasi-emulated-* libs."
            );
        }

        println!("cargo:rustc-link-lib=wasi-emulated-signal");
        println!("cargo:rustc-link-lib=wasi-emulated-process-clocks");
        println!("cargo:rustc-link-lib=wasi-emulated-mman");
        println!("cargo:rustc-link-lib=wasi-emulated-getpid");
    }
}

fn find_wasi_sysroot_libdir(target: &str) -> Option<PathBuf> {
    let env_vars = ["WASI_SDK_PATH", "WASI_SDK_ROOT", "WASI_SDK"];

    for var in env_vars {
        println!("cargo:rerun-if-env-changed={var}");
        if let Ok(base) = env::var(var) {
            let candidate = PathBuf::from(&base)
                .join("share")
                .join("wasi-sysroot")
                .join("lib")
                .join(target);
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }

    let mut candidates = Vec::new();
    if let Ok(home) = env::var("HOME") {
        let home_path = PathBuf::from(home);
        candidates.push(home_path.join("wasi-sdk"));
        if let Ok(entries) = fs::read_dir(&home_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("wasi-sdk-") {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    candidates.push(PathBuf::from("/opt/wasi-sdk"));
    candidates.push(PathBuf::from("/usr/local/wasi-sdk"));

    for base in candidates {
        let candidate = base
            .join("share")
            .join("wasi-sysroot")
            .join("lib")
            .join(target);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    None
}
