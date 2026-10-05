// Starts Qt, makes Atlas Archive single-instance and loads the window. A
// second launch (an archive double-clicked in Explorer, `atlas-archive
// --extract-here <file>`) hands its arguments to this one and exits; they are
// read in Rust (src/backend.rs), never here.
#include <atlas/app.h>

#include <KDBusService>
#include <KWindowSystem>

#include <QApplication>
#include <QCommandLineParser>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QQmlApplicationEngine>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QUrl>

#include <memory>

// Defined in src/lib.rs.
extern "C" void *atlas_backend_new();

// Hands a launch's arguments (without the program name) to the backend.
static void activate(QObject *backend, const QStringList &arguments, const QString &cwd)
{
    if (!QMetaObject::invokeMethod(backend, "activate", Q_ARG(QStringList, arguments), Q_ARG(QString, cwd))) {
        qWarning("atlas-archive: the backend did not take the launch arguments");
    }
}

// Shows `path` in the file manager: org.freedesktop.FileManager1.ShowItems,
// and the folder in the default handler if no file manager answers it. Never
// waits for the answer.
static void showInFileManager(const QString &path)
{
    const QString uri = QUrl::fromLocalFile(path).toString(QUrl::FullyEncoded);
    const QString folder = QFileInfo(path).isDir() ? path : QFileInfo(path).absolutePath();
    QDBusMessage message = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.FileManager1"),
                                                          QStringLiteral("/org/freedesktop/FileManager1"),
                                                          QStringLiteral("org.freedesktop.FileManager1"),
                                                          QStringLiteral("ShowItems"));
    message << QStringList{uri} << QString();
    auto *watcher = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(message, 5000));
    QObject::connect(watcher, &QDBusPendingCallWatcher::finished, watcher, [watcher, folder] {
        if (watcher->isError()) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
        }
        watcher->deleteLater();
    });
}

// Receives the backend's showFilesRequested signal.
class FileManagerBridge : public QObject
{
    Q_OBJECT
public Q_SLOTS:
    void show(const QString &path)
    {
        showInFileManager(path);
    }
};

static void raise(QQmlApplicationEngine *engine)
{
    auto *window = qobject_cast<QQuickWindow *>(engine->rootObjects().value(0));
    if (!window) {
        return;
    }
    if (window->visibility() == QWindow::Minimized) {
        window->showNormal();
    } else {
        window->show();
    }
    // The launcher's activation token: without it Wayland keeps the window
    // down.
    KWindowSystem::updateStartupId(window);
    KWindowSystem::activateWindow(window);
}

int main(int argc, char *argv[])
{
    atlas_app_init();
    // Drawn on the CPU like the other Atlas apps unless QT_QUICK_BACKEND says
    // otherwise (the P phase measures a 50k-row list both ways).
    if (qEnvironmentVariableIsEmpty("QT_QUICK_BACKEND")) {
        QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);
    }

    QApplication app(argc, argv);
    atlas_app_ready();

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("The archive manager of AtlasOS."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("extract-here"), QStringLiteral("Extract each archive next to it.")});
    parser.addOption({QStringLiteral("extract-to-folder"), QStringLiteral("Extract each archive into a folder named like it, next to it.")});
    parser.addPositionalArgument(QStringLiteral("files"), QStringLiteral("The archive to open, or the archives to extract."), QStringLiteral("[files...]"));
    // Only --help and --version are acted on here. Every other argument goes
    // to the backend, which alone decides what is valid and says what it
    // refused in the window, so the two never disagree.
    parser.parse(QCoreApplication::arguments());
    if (parser.isSet(QStringLiteral("help"))) {
        parser.showHelp();
    }
    if (parser.isSet(QStringLiteral("version"))) {
        parser.showVersion();
    }

    // One instance per session. A second launch's arguments come here through
    // activateRequested; without a session bus each launch runs on its own.
    KDBusService service(KDBusService::Unique | KDBusService::NoExitOnFailure);

    // The backend outlives the engine: the window's bindings read it until
    // the engine is gone.
    std::unique_ptr<QObject> backend(static_cast<QObject *>(atlas_backend_new()));
    auto engine = std::make_unique<QQmlApplicationEngine>();
    QObject::connect(engine.get(), &QQmlApplicationEngine::objectCreationFailed, &app, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine->setInitialProperties({{QStringLiteral("backend"), QVariant::fromValue(backend.get())}});
    engine->loadFromModule("net.eterneon.atlas.archive", "Main");
    if (engine->rootObjects().isEmpty()) {
        return 1;
    }

    // Show Files in the job view.
    FileManagerBridge files;
    QObject::connect(backend.get(), SIGNAL(showFilesRequested(QString)), &files, SLOT(show(QString)));
    // A second launch. With nothing but the program name (the launcher
    // icon, the taskbar) the window only comes up, keeping its place.
    QObject::connect(&service, &KDBusService::activateRequested, backend.get(),
                     [e = engine.get(), b = backend.get()](const QStringList &arguments, const QString &cwd) {
                         raise(e);
                         if (arguments.size() > 1) {
                             // The Rust side reads 64; one more lets it say some were left out.
                             activate(b, arguments.mid(1, 65), cwd);
                         }
                     });
    // org.freedesktop.Application.Open from any process in the session: files
    // only, and no folder, so relative paths are refused.
    QObject::connect(&service, &KDBusService::openRequested, backend.get(), [e = engine.get(), b = backend.get()](const QList<QUrl> &urls) {
        raise(e);
        if (urls.isEmpty()) {
            return;
        }
        // `--` first: whatever the caller sent is never read as an option.
        QStringList arguments{QStringLiteral("--")};
        // The Rust side looks at 64 arguments (this `--` and 63 URLs) and
        // counts the rest; one more is enough for it to say some were left
        // out.
        for (const QUrl &url : urls.mid(0, 64)) {
            arguments << url.toString(QUrl::FullyEncoded);
        }
        activate(b, arguments, QString());
    });
    activate(backend.get(), QCoreApplication::arguments().mid(1), QDir::currentPath());

    const int code = app.exec();
    engine.reset();
    return code;
}

#include "main.moc"
