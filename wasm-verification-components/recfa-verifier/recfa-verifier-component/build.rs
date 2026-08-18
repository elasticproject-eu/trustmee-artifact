//! Compiles the vendored upstream ReCFA verifier (C++) and links it into the
//! component.
//!
//! For `wasm32-*` targets this needs wasi-sdk, located via (in order):
//!   1. `WASI_SDK_PATH`
//!   2. `$HOME/wasi-sdk`
//!   3. `/opt/wasi-sdk`
//!
//! Notes on the flags:
//!   * `-fno-exceptions` — clang's `-fwasm-exceptions` currently emits *legacy*
//!     EH opcodes, which the wasmtime version this repo pins rejects. The
//!     vendored verifier never throws (see vendor/patch-upstream.py: the four
//!     upstream `exit(-1)` sites became flag + early return), so disabling EH
//!     costs nothing and keeps the module portable.
//!   * `_WASI_EMULATED_PROCESS_CLOCKS` — upstream calls `clock()` purely to
//!     report timing; WASI has no process clock, so we link the emulation.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn wasi_sdk() -> PathBuf {
    if let Ok(p) = env::var("WASI_SDK_PATH") {
        let p = PathBuf::from(p);
        if p.join("bin/clang++").exists() {
            return p;
        }
        panic!("WASI_SDK_PATH={} has no bin/clang++", p.display());
    }
    let mut candidates = Vec::new();
    if let Ok(home) = env::var("HOME") {
        candidates.push(PathBuf::from(home).join("wasi-sdk"));
    }
    candidates.push(PathBuf::from("/opt/wasi-sdk"));
    for c in &candidates {
        if c.join("bin/clang++").exists() {
            return c.clone();
        }
    }
    panic!(
        "wasi-sdk not found. Set WASI_SDK_PATH, or install it to $HOME/wasi-sdk \
         or /opt/wasi-sdk. Tried: {:?}",
        candidates
    );
}

fn run(cmd: &mut Command) {
    let rendered = format!("{cmd:?}");
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {rendered}: {e}"));
    if !status.success() {
        panic!("command failed ({status}): {rendered}");
    }
}

fn main() {
    let vendor = Path::new("vendor");
    println!("cargo:rerun-if-changed=vendor/check.cpp");
    println!("cargo:rerun-if-changed=vendor/recfa_entry.h");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WASI_SDK_PATH");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target = env::var("TARGET").unwrap();
    let obj = out_dir.join("check.o");
    let lib = out_dir.join("librecfa_check.a");

    let common = [
        "-std=gnu++14",
        "-O2",
        "-fno-exceptions",
        "-fno-rtti",
        // upstream is warning-noisy; the port fixes the one that mattered
        // (the dangling c_str()), the rest are cosmetic
        "-w",
        "-c",
    ];

    if target.starts_with("wasm32") {
        let sdk = wasi_sdk();
        let clang = sdk.join("bin/clang++");
        let ar = sdk.join("bin/llvm-ar");
        let sysroot = sdk.join("share/wasi-sysroot");

        // wasm32-wasip2 -> wasm32-wasip2, wasm32-wasip1 -> wasm32-wasip1
        let clang_target = if target.contains("wasip2") {
            "wasm32-wasip2"
        } else {
            "wasm32-wasip1"
        };

        let mut cmd = Command::new(&clang);
        cmd.arg(format!("--target={clang_target}"))
            .args(common)
            .arg("-D_WASI_EMULATED_PROCESS_CLOCKS")
            .arg("-I")
            .arg(vendor)
            .arg(vendor.join("check.cpp"))
            .arg("-o")
            .arg(&obj);
        run(&mut cmd);

        run(Command::new(&ar).arg("rcs").arg(&lib).arg(&obj));

        // C++ runtime + the clock() emulation, from wasi-sdk's sysroot.
        let libdir = sysroot.join("lib").join(clang_target);
        println!("cargo:rustc-link-search=native={}", libdir.display());
        println!(
            "cargo:rustc-link-search=native={}",
            libdir.join("noeh").display()
        );
        println!("cargo:rustc-link-lib=static=c++");
        println!("cargo:rustc-link-lib=static=c++abi");
        println!("cargo:rustc-link-lib=static=wasi-emulated-process-clocks");
    } else {
        // Native build, so the crate stays compilable (and the C++ testable)
        // off-target.
        let cxx = env::var("CXX").unwrap_or_else(|_| "c++".to_string());
        let mut cmd = Command::new(cxx);
        cmd.args(common)
            .arg("-fPIC")
            .arg("-I")
            .arg(vendor)
            .arg(vendor.join("check.cpp"))
            .arg("-o")
            .arg(&obj);
        run(&mut cmd);
        run(Command::new("ar").arg("rcs").arg(&lib).arg(&obj));
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=recfa_check");
}
