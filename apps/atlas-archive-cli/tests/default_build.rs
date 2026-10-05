//! The shipped build (no `dev-worker` feature): the worker is the installed
//! one and nothing on the command line can pick another.
#![cfg(not(feature = "dev-worker"))]

use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_atlas-archive-cli");

#[test]
fn a_worker_option_is_refused_before_anything_runs() {
    for args in [
        &["--worker=/bin/true", "list", "a.zip"][..],
        &["--worker", "/bin/true", "list", "a.zip"],
        &["list", "--worker=/bin/true", "a.zip"],
        &["extract", "--worker", "/bin/true", "a.zip"],
    ] {
        let out = Command::new(CLI)
            .args(args)
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .output()
            .expect("the CLI starts");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(err.contains("Unknown option"), "{args:?}: {err}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn the_help_doesnt_mention_a_worker_option() {
    let out = Command::new(CLI).arg("--help").output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("--worker"));
}
