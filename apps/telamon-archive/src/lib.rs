//! Rust side of Telamon Archive. `cpp/main.cpp` starts Qt and the
//! single-instance service; everything else lives here as QObjects exposed to
//! QML, over the Qt-free `telamon-archive-core`. Archive bytes are never parsed
//! in this process: the sandboxed worker does that (docs/DESIGN.md).

mod backend;
mod job;
mod view;

telamon_framework_ui::app! {
    name: "Telamon Archive",
    id: "net.eterneon.telamon.archive",
    repo: "atlasos-archive",
    ui: "2.0.0",
}

use std::ffi::c_void;

/// Called once from `main.cpp`. Returns the `Backend` QObject, which C++ hands
/// to the QML engine. Ownership passes to the caller (a QObject with no parent).
#[unsafe(no_mangle)]
pub extern "C" fn telamon_backend_new() -> *mut c_void {
    backend::qobject::backend_make_unique().into_raw().cast()
}
