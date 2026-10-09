cmake_minimum_required(VERSION 3.24)
project(telamon-archive VERSION 0.4.0 LANGUAGES CXX)

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

# -DTELAMON_ARCHIVE_FEATURES=dev-worker is for smoke tests only: a worker named
# by $TELAMON_ARCHIVE_WORKER, unsandboxed. Never in a shipped build.
set(TELAMON_ARCHIVE_FEATURES "" CACHE STRING "Cargo features of the telamon-archive crate (tests only)")

# Rust library (CXX-Qt QObjects, atlas-framework, telamon-archive-core) and the
# two Rust programs: the CLI and the sandboxed worker. cxx-qt-build finds Qt
# via $QMAKE.
find_program(QMAKE6 NAMES qmake6 qmake REQUIRED)
corrosion_import_crate(MANIFEST_PATH ${WORKSPACE_DIR}/Cargo.toml
    CRATES telamon-archive telamon-archive-cli telamon-archive-worker LOCKED)
if(TELAMON_ARCHIVE_FEATURES)
    corrosion_set_features(telamon_archive FEATURES ${TELAMON_ARCHIVE_FEATURES})
endif()
corrosion_set_env_vars(telamon_archive QMAKE=${QMAKE6})

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
set(TELAMON_UI_CRATE_DIR "")
foreach(i RANGE ${LAST_PACKAGE})
    string(JSON PKG_NAME GET "${CARGO_METADATA}" packages ${i} name)
    if(PKG_NAME STREQUAL "telamon-framework-ui")
        string(JSON PKG_MANIFEST GET "${CARGO_METADATA}" packages ${i} manifest_path)
        get_filename_component(TELAMON_UI_CRATE_DIR "${PKG_MANIFEST}" DIRECTORY)
    endif()
endforeach()
if(NOT EXISTS "${TELAMON_UI_CRATE_DIR}/include/telamon/app.h")
    message(FATAL_ERROR "telamon-framework-ui's include/telamon/app.h not found (looked in '${TELAMON_UI_CRATE_DIR}')")
endif()

# Telamon.Ui, the shared Telamon look, is installed like Kirigami (telamon-ui, from
# atlas-framework): QML imports it and nothing links it. qmlcachegen and
# qmllint read its types from the installed copy.
if(NOT EXISTS "${QT6_INSTALL_PREFIX}/${QT6_INSTALL_QML}/Telamon/Ui/qmldir")
    message(FATAL_ERROR "Telamon.Ui is not installed: install telamon-ui (atlas-framework)")
endif()

qt_add_executable(telamon-archive-app cpp/main.cpp cpp/service.cpp cpp/service.h cpp/archive1.cpp cpp/archive1.h cpp/ffi.h)
set_target_properties(telamon-archive-app PROPERTIES OUTPUT_NAME telamon-archive)
target_include_directories(telamon-archive-app PRIVATE "${TELAMON_UI_CRATE_DIR}/include" ${CMAKE_CURRENT_SOURCE_DIR}/cpp)

# qmlcachegen compiles every QML file to C++ at build time; the app reads no
# .qml from disk at run time.
qt_add_qml_module(telamon-archive-app
    URI net.eterneon.telamon.archive
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/ArchiveView.qml
        qml/JobView.qml
        qml/JobWindow.qml
        qml/JobWindows.qml
        qml/Questions.qml
)

target_link_libraries(telamon-archive-app PRIVATE
    telamon_archive
    Qt6::Core Qt6::Gui Qt6::DBus Qt6::Qml Qt6::Quick Qt6::QuickControls2 Qt6::Widgets
    KF6::DBusAddons KF6::WindowSystem)

install(TARGETS telamon-archive-app RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS $<TARGET_FILE:telamon-archive-cli> DESTINATION ${CMAKE_INSTALL_BINDIR})
# Started only by the app and the CLI, never from a PATH.
install(PROGRAMS $<TARGET_FILE:telamon-archive-worker> DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/telamon-archive)
install(FILES data/net.eterneon.telamon.archive.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
# Explorer and Dolphin read KDE service menus: the right-click actions.
install(FILES data/net.eterneon.telamon.archive.servicemenu.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/kio/servicemenus
        RENAME net.eterneon.telamon.archive.desktop)
# Archive1 on the session bus (docs/DESIGN.md, "The API other apps call"): the
# bus starts the program without a window, and it leaves when it is idle.
configure_file(data/net.eterneon.telamon.archive.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/net.eterneon.telamon.archive.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/net.eterneon.telamon.archive.service
        DESTINATION ${CMAKE_INSTALL_DATADIR}/dbus-1/services)
install(FILES data/net.eterneon.telamon.archive.metainfo.xml
        DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
install(FILES data/net.eterneon.telamon.archive.svg
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)

# What this app was called until 0.2.0 (Atlas Archive), for one release: the
# image and the apps that call it (Explorer, the launcher) still use the old
# names, and move to the new ones one by one. Remove with data/legacy.
#   the programs by their old names,
install(CODE "
    file(MAKE_DIRECTORY \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}\")
    foreach(pair \"telamon-archive;atlas-archive\" \"telamon-archive-cli;atlas-archive-cli\")
        list(GET pair 0 target)
        list(GET pair 1 link)
        file(REMOVE \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/\${link}\")
        file(CREATE_LINK \"\${target}\" \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/\${link}\" SYMBOLIC)
    endforeach()
")
#   the old desktop file (hidden, same MimeType list and the same program),
install(FILES data/legacy/net.eterneon.atlas.archive.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
#   the old bus name (net.eterneon.atlas.archive starts the same program),
configure_file(data/legacy/net.eterneon.atlas.archive.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/net.eterneon.atlas.archive.service @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/net.eterneon.atlas.archive.service
        DESTINATION ${CMAKE_INSTALL_DATADIR}/dbus-1/services)
#   and the old service menu file, empty so the actions aren't shown twice.
install(FILES data/legacy/net.eterneon.atlas.archive.servicemenu.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/kio/servicemenus
        RENAME net.eterneon.atlas.archive.desktop)
