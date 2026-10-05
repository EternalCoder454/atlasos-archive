//! The window's entry point: what a launch asks for. `main.cpp` calls
//! `activate` with the first launch's arguments and with each forwarded
//! second launch's. The F phase reads them in `atlas-archive-core`; until
//! then they are only counted.

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
        include!("cxx-qt-lib/qstringlist.h");
        type QStringList = cxx_qt_lib::QStringList;
    }

    extern "RustQt" {
        #[qobject]
        #[namespace = "atlas_archive"]
        type Backend = super::BackendRust;

        /// Handles a launch's arguments (without the program name), relative
        /// paths read against `cwd`.
        #[qinvokable]
        fn activate(self: Pin<&mut Backend>, args: &QStringList, cwd: &QString);
    }

    impl cxx_qt::Threading for Backend {}

    #[namespace = "rust::cxxqtlib1"]
    unsafe extern "C++" {
        include!("cxx-qt-lib/common.h");

        #[cxx_name = "make_unique"]
        fn backend_make_unique() -> UniquePtr<Backend>;
    }
}

use core::pin::Pin;
use cxx_qt_lib::{QString, QStringList};

#[derive(Default)]
pub struct BackendRust {}

impl qobject::Backend {
    pub fn activate(self: Pin<&mut Self>, args: &QStringList, _cwd: &QString) {
        // Arguments are untrusted; nothing of them is logged until they have
        // been checked.
        let count = args.len().max(0);
        if count > 0 {
            log::info!("launch with {count} arguments (not handled yet)");
        }
    }
}
