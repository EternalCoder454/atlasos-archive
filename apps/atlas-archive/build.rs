use cxx_qt_build::CxxQtBuilder;

fn main() {
    // Generates the C++ for the QObject bridges and compiles it into the Rust
    // static library. Qt is found through $QMAKE (CMake sets it).
    CxxQtBuilder::new().file("src/backend.rs").build();
}
