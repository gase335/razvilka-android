// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#![cfg_attr(all(windows, not(debug_assertions), feature = "gui"), windows_subsystem = "windows")]

use razvilka::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let first = args.get(1).map(String::as_str).unwrap_or("");
    match first {
        "--core" => std::process::exit(childhost::run_core_child()),
        #[cfg(feature = "mock")]
        "--mock-core" => std::process::exit(mock::run_mock_core()),
        #[cfg(feature = "webview")]
        "--webview" => std::process::exit(webview::run(&args[2..])),
        "--headless" => std::process::exit(headless::run(&args[2..])),
        "--version" => {
            println!("Razvilka {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            #[cfg(feature = "gui")]
            gui::run(&args[1..]);
            #[cfg(not(feature = "gui"))]
            std::process::exit(headless::run(&args[1..]));
        }
    }
}
