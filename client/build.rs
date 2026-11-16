// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Ресурсы Windows (иконка, манифест, версия) — через windres из MinGW.
fn main() {
    println!("cargo:rerun-if-changed=resources/razvilka.rc");
    println!("cargo:rerun-if-changed=resources/razvilka.ico");
    println!("cargo:rerun-if-changed=resources/razvilka.manifest");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    let rc = std::path::Path::new("resources/razvilka.rc");
    if !rc.exists() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("razvilka_res.o");
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".into());
    let status = std::process::Command::new(&windres)
        .args(["--input", "resources/razvilka.rc", "--output-format=coff", "--output"])
        .arg(&out)
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg-bins={}", out.display());
        }
        other => println!("cargo:warning=windres не выполнен ({other:?}) — exe без иконки"),
    }
}
