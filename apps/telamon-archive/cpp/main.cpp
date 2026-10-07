// Starts Qt, makes Telamon Archive single-instance and loads the window. A
// second launch (an archive double-clicked in Explorer, `telamon-archive
// --extract-here <file>`) hands its arguments to this one and exits; they are
// read in Rust (src/backend.rs), never here.
#include <telamon/app.h>

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
extern "C" void *telamon_backend_new();

// Hands a launch's arguments (without the program name) to the backend.
static void activate(QObject *backend, const QStringList &arguments, const QString &cwd)
{
    if (!QMetaObject::invokeMethod(backend, "activate", Q_ARG(QStringList, arguments), Q_ARG(QString, cwd))) {
        qWarning("telamon-archive: the backend did not take the launch arguments");
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

// Telamon Archive was Atlas Archive until 0.2.0: `net.eterneon.atlas.archive`
// was its D-Bus name, and the apps that call it (Explorer, the launcher, the
// image's scripts) change names one by one. While they do, the same session
// instance also answers org.freedesktop.Application on the old name and
// path, by passing every call to the signals of the KDBusService, so it
// takes the new name's path through the same handlers. Remove it with the
// legacy desktop files in data/legacy.
class LegacyApplication : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.Application")
public:
    explicit LegacyApplication(KDBusService *service)
        : QObject(service)
        , m_service(service)
    {
    }

public Q_SLOTS:
    void Activate(const QVariantMap &platformData)
    {
        applyToken(platformData);
        Q_EMIT m_service->activateRequested(QStringList(), QString());
    }
    void Open(const QStringList &uris, const QVariantMap &platformData)
    {
        applyToken(platformData);
        QList<QUrl> urls;
        for (const QString &uri : uris) {
            urls << QUrl::fromUserInput(uri);
        }
        Q_EMIT m_service->openRequested(urls);
    }
    void ActivateAction(const QString &actionName, const QVariantList &parameter, const QVariantMap &platformData)
    {
        applyToken(platformData);
        Q_EMIT m_service->activateActionRequested(actionName, parameter);
    }

private:
    static void applyToken(const QVariantMap &platformData)
    {
        // What KDBusService does with the launcher's token, so the window
        // can take focus on Wayland.
        const QString token = platformData.value(QStringLiteral("activation-token")).toString();
        if (!token.isEmpty()) {
            KWindowSystem::setCurrentXdgActivationToken(token);
        }
    }

    KDBusService *m_service;
};

static const char legacyBusName[] = "net.eterneon.atlas.archive";
static const char legacyObjectPath[] = "/net/eterneon/atlas/archive";

static void serveLegacyName(KDBusService *service)
{
    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        return;
    }
    auto *legacy = new LegacyApplication(service);
    if (!bus.registerObject(QLatin1String(legacyObjectPath), legacy, QDBusConnection::ExportAllSlots)) {
        qWarning("telamon-archive: could not serve %s", legacyObjectPath);
        return;
    }
    // Without queueing: another owner (an Atlas Archive 0.1 still running
    // through an upgrade) keeps the name, and callers get that instance.
    if (!bus.registerService(QLatin1String(legacyBusName))) {
        qWarning("telamon-archive: %s is taken by another program; only the new name answers", legacyBusName);
    }
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
    telamon_app_init();
    // Drawn on the CPU like the other Telamon apps unless QT_QUICK_BACKEND says
    // otherwise (the P phase measures a 50k-row list both ways).
    if (qEnvironmentVariableIsEmpty("QT_QUICK_BACKEND")) {
        QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);
    }

    QApplication app(argc, argv);
    telamon_app_ready();

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("The archive manager of Telamon OS."));
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
    std::unique_ptr<QObject> backend(static_cast<QObject *>(telamon_backend_new()));
    auto engine = std::make_unique<QQmlApplicationEngine>();
    QObject::connect(engine.get(), &QQmlApplicationEngine::objectCreationFailed, &app, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine->setInitialProperties({{QStringLiteral("backend"), QVariant::fromValue(backend.get())}});
    engine->loadFromModule("net.eterneon.telamon.archive", "Main");
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
    // Last, once the handlers above are connected.
    serveLegacyName(&service);
    activate(backend.get(), QCoreApplication::arguments().mid(1), QDir::currentPath());

    const int code = app.exec();
    engine.reset();
    return code;
}

#include "main.moc"
