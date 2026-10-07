cmake_minimum_required(VERSION 3.24)
project(atlas-archive VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX /usr CACHE PATH "" FORCE)
endif()
include(GNUInstallDirs)
find_package(Qt6 6.11 REQUIRED COMPONENTS Core Gui DBus Qml Quick QuickControls2 Widgets)
qt_policy(SET QTP0001 NEW)
qt_policy(SET QTP0004 NEW)
# telamon-framework-ui's startup code (single instance, window activation)
find_package(KF6DBusAddons REQUIRED)
find_package(KF6WindowSystem REQUIRED)
find_package(Corrosion REQUIRED)

set(WORKSPACE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# -DATLAS_ARCHIVE_FEATURES=dev-worker is for smoke tests only: a worker named
# by $ATLAS_ARCHIVE_WORKER, unsandboxed. Never in a shipped build.
set(ATLAS_ARCHIVE_FEATURES "" CACHE STRING "Cargo features of the atlas-archive crate (tests only)")

# Rust library (CXX-Qt QObjects, atlas-framework, atlas-archive-core) and the
# two Rust programs: the CLI and the sandboxed worker. cxx-qt-build finds Qt
# via $QMAKE.
find_program(QMAKE6 NAMES qmake6 qmake REQUIRED)
corrosion_import_crate(MANIFEST_PATH ${WORKSPACE_DIR}/Cargo.toml
    CRATES atlas-archive atlas-archive-cli atlas-archive-worker LOCKED)
if(ATLAS_ARCHIVE_FEATURES)
    corrosion_set_features(atlas_archive FEATURES ${ATLAS_ARCHIVE_FEATURES})
endif()
corrosion_set_env_vars(atlas_archive QMAKE=${QMAKE6})

# The framework's C header (telamon/app.h) comes with the crate's sources,
# wherever cargo put them (a git checkout in ~/.cargo).
find_program(CARGO NAMES cargo REQUIRED)
execute_process(
    COMMAND ${CARGO} metadata --format-version 1 --locked --manifest-path ${WORKSPACE_DIR}/Cargo.toml
    OUTPUT_VARIABLE CARGO_METADATA
    RESULT_VARIABLE CARGO_METADATA_RESULT
    ERROR_VARIABLE CARGO_METADATA_ERROR
    TIMEOUT 300)
if(NOT CARGO_METADATA_RESULT EQUAL 0)
    message(FATAL_ERROR "cargo metadata failed (${CARGO_METADATA_RESULT}): ${CARGO_METADATA_ERROR}\n"
        "Run `cargo fetch --locked` first, or check the network.")
endif()
string(JSON NPACKAGES LENGTH "${CARGO_METADATA}" packages)
math(EXPR LAST_PACKAGE "${NPACKAGES} - 1")
set(ATLAS_UI_CRATE_DIR "")
foreach(i RANGE ${LAST_PACKAGE})
    string(JSON PKG_NAME GET "${CARGO_METADATA}" packages ${i} name)
    if(PKG_NAME STREQUAL "telamon-framework-ui")
        string(JSON PKG_MANIFEST GET "${CARGO_METADATA}" packages ${i} manifest_path)
        get_filename_component(ATLAS_UI_CRATE_DIR "${PKG_MANIFEST}" DIRECTORY)
    endif()
endforeach()
if(NOT EXISTS "${ATLAS_UI_CRATE_DIR}/include/telamon/app.h")
    message(FATAL_ERROR "telamon-framework-ui's include/telamon/app.h not found (looked in '${ATLAS_UI_CRATE_DIR}')")
endif()

# Telamon.Ui, the shared Atlas look, is installed like Kirigami (telamon-ui, from
# atlas-framework): QML imports it and nothing links it. qmlcachegen and
# qmllint read its types from the installed copy.
if(NOT EXISTS "${QT6_INSTALL_PREFIX}/${QT6_INSTALL_QML}/Telamon/Ui/qmldir")
    message(FATAL_ERROR "Telamon.Ui is not installed: install telamon-ui (atlas-framework)")
endif()

qt_add_executable(atlas-archive-app cpp/main.cpp)
set_target_properties(atlas-archive-app PROPERTIES OUTPUT_NAME atlas-archive)
target_include_directories(atlas-archive-app PRIVATE "${ATLAS_UI_CRATE_DIR}/include")

# qmlcachegen compiles every QML file to C++ at build time; the app reads no
# .qml from disk at run time.
qt_add_qml_module(atlas-archive-app
    URI net.eterneon.atlas.archive
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/ArchiveView.qml
        qml/JobView.qml
        qml/Questions.qml
)

target_link_libraries(atlas-archive-app PRIVATE
    atlas_archive
    Qt6::Core Qt6::Gui Qt6::DBus Qt6::Qml Qt6::Quick Qt6::QuickControls2 Qt6::Widgets
    KF6::DBusAddons KF6::WindowSystem)

install(TARGETS atlas-archive-app RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS $<TARGET_FILE:atlas-archive-cli> DESTINATION ${CMAKE_INSTALL_BINDIR})
# Started only by the app and the CLI, never from a PATH.
install(PROGRAMS $<TARGET_FILE:atlas-archive-worker> DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/atlas-archive)
install(FILES data/net.eterneon.atlas.archive.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
# Explorer and Dolphin read KDE service menus: the right-click actions.
install(FILES data/net.eterneon.atlas.archive.servicemenu.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/kio/servicemenus
        RENAME net.eterneon.atlas.archive.desktop)
install(FILES data/net.eterneon.atlas.archive.metainfo.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
install(FILES data/net.eterneon.atlas.archive.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
