// Starts Qt, makes Telamon Archive single-instance, serves the Archive1 D-Bus
// API (archive1.cpp) and loads the windows. A second launch (an archive
// double-clicked in Explorer, `telamon-archive --extract-here <file>`) hands
// its arguments to this one and exits; they are read in Rust
// (src/backend.rs), never here.
//
// `telamon-archive --service` is what D-Bus activation runs for an API call:
// no window comes up unless a job needs one, and the program exits when it is
// idle (no window, no job, not even a finished one still being kept for its
// caller) for a few seconds.
#include <telamon/app.h>

#include "archive1.h"
#include "service.h"

#include <KDBusService>
#include <KWindowSystem>

#include <QApplication>
#include <QCommandLineParser>
#include <QDBusConnection>
#include <QElapsedTimer>
#include <QPointer>
#include <QTimer>
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

static void serveLegacyName(KDBusService *service, Archive1Core *core)
{
    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        return;
    }
    auto *legacy = new LegacyApplication(service);
    // The old name's Archive1 (net.eterneon.atlas.Archive1) hangs off the same object.
    new AtlasArchive1Adaptor(legacy, core);
    if (!bus.registerObject(QLatin1String(legacyObjectPath), legacy, QDBusConnection::ExportAllSlots | QDBusConnection::ExportAdaptors)) {
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

static void raise(QQuickWindow *window)
{
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

// The program's arguments without `--service`, which is for this file only.
static QStringList withoutService(const QStringList &arguments)
{
    QStringList out = arguments;
    out.removeAll(QStringLiteral("--service"));
    return out;
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
    // The program ends when it has nothing to show or do (see `idleCheck`),
    // not when a window closes: jobs go on without one.
    app.setQuitOnLastWindowClosed(false);

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("The archive manager of Telamon OS."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("extract-here"), QStringLiteral("Extract each archive next to it.")});
    parser.addOption({QStringLiteral("extract-to-folder"), QStringLiteral("Extract each archive into a folder named like it, next to it.")});
    parser.addOption({QStringLiteral("service"), QStringLiteral("Serve the D-Bus API without a window (what D-Bus activation runs).")});
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
    const QStringList launchArguments = withoutService(QCoreApplication::arguments().mid(1));

    // One instance per session. A second launch's arguments come here through
    // activateRequested; without a session bus each launch runs on its own.
    KDBusService service(KDBusService::Unique | KDBusService::NoExitOnFailure);

    // The jobs (Rust), their windows, and the Archive1 API on the bus.
    JobsService jobs;
    if (!jobs.start()) {
        qWarning("telamon-archive: the job service did not start");
    }
    Archive1Core api(&jobs);
    new TelamonArchive1Adaptor(&service, &api);

    // The backend outlives the engine: the window's bindings read it until
    // the engine is gone.
    std::unique_ptr<QObject> backend(static_cast<QObject *>(telamon_backend_new()));
    auto engine = std::make_unique<QQmlApplicationEngine>();
    QObject::connect(engine.get(), &QQmlApplicationEngine::objectCreationFailed, &app, [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);

    // The archive window is made when something needs it: not for an API call
    // that only runs jobs.
    QPointer<QQuickWindow> mainWindow;
    auto ensureMain = [&]() -> QQuickWindow * {
        if (mainWindow) {
            return mainWindow;
        }
        engine->setInitialProperties({{QStringLiteral("backend"), QVariant::fromValue(backend.get())}});
        const int before = engine->rootObjects().size();
        engine->loadFromModule("net.eterneon.telamon.archive", "Main");
        for (int i = before; i < engine->rootObjects().size(); ++i) {
            if (auto *w = qobject_cast<QQuickWindow *>(engine->rootObjects().at(i))) {
                mainWindow = w;
            }
        }
        return mainWindow;
    };

    // The job windows: progress, questions, and the Extract All and Compress
    // dialogs.
    engine->setInitialProperties({{QStringLiteral("service"), QVariant::fromValue(&jobs)}});
    engine->loadFromModule("net.eterneon.telamon.archive", "JobWindows");
    if (engine->rootObjects().isEmpty()) {
        return 1;
    }

    const bool serviceOnly = parser.isSet(QStringLiteral("service")) && launchArguments.isEmpty();
    if (!serviceOnly && !ensureMain()) {
        return 1;
    }

    // Show Files in the job views.
    FileManagerBridge files;
    QObject::connect(backend.get(), SIGNAL(showFilesRequested(QString)), &files, SLOT(show(QString)));
    QObject::connect(&jobs, &JobsService::showFilesRequested, &files, &FileManagerBridge::show);
    // A second launch. With nothing but the program name (the launcher
    // icon, the taskbar) the window only comes up, keeping its place.
    QObject::connect(&service, &KDBusService::activateRequested, backend.get(), [&](const QStringList &arguments, const QString &cwd) {
        const QStringList rest = withoutService(arguments.mid(1));
        if (arguments.mid(1) == QStringList{QStringLiteral("--service")}) {
            // Another service start: there is one already.
            return;
        }
        raise(ensureMain());
        if (!rest.isEmpty()) {
            // The Rust side reads 64; one more lets it say some were left out.
            activate(backend.get(), rest.mid(0, 65), cwd);
        }
    });
    // org.freedesktop.Application.Open from any process in the session: files
    // only, and no folder, so relative paths are refused.
    QObject::connect(&service, &KDBusService::openRequested, backend.get(), [&](const QList<QUrl> &urls) {
        raise(ensureMain());
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
        activate(backend.get(), arguments, QString());
    });
    // The desktop file's actions, for launchers that use D-Bus activation:
    // the same as `--extract-here` and `--extract-to-folder` with the files.
    QObject::connect(&service, &KDBusService::activateActionRequested, backend.get(), [&](const QString &action, const QVariant &parameterValue) {
        const QVariantList parameter = parameterValue.toList();
        const QString option = action == QLatin1String("ExtractHere") ? QStringLiteral("--extract-here") : action == QLatin1String("ExtractToFolder") ? QStringLiteral("--extract-to-folder") : QString();
        QStringList arguments;
        for (const QVariant &p : parameter.mid(0, 64)) {
            arguments << p.toString();
        }
        if (option.isEmpty() || arguments.isEmpty()) {
            raise(ensureMain());
            return;
        }
        raise(ensureMain());
        arguments.prepend(QStringLiteral("--"));
        arguments.prepend(option);
        activate(backend.get(), arguments, QString());
    });
    // Archive1.Open: the archive window, over the caller's window.
    QObject::connect(&api, &Archive1Core::openRequested, backend.get(), [&](const QString &path, const QString &token, const QString &parent) {
        JobsService::useToken(token);
        QQuickWindow *w = ensureMain();
        if (w && parent.startsWith(QLatin1String("x11:")) && QGuiApplication::platformName() == QLatin1String("xcb")) {
            bool ok = false;
            const WId id = parent.mid(4).toULongLong(&ok, 16);
            if (ok && id != 0) {
                raise(w);
                KWindowSystem::setMainWindow(w, id);
                w = nullptr;
            }
        } else if (w && parent.startsWith(QLatin1String("wayland:"))) {
            raise(w);
            KWindowSystem::setMainWindow(w, parent.mid(8));
            w = nullptr;
        }
        raise(w);
        activate(backend.get(), {QStringLiteral("--"), QUrl::fromLocalFile(path).toString(QUrl::FullyEncoded)}, QString());
    });
    // Last, once the handlers above are connected.
    serveLegacyName(&service, &api);
    if (!launchArguments.isEmpty()) {
        activate(backend.get(), launchArguments, QDir::currentPath());
    }

    // Ends the program when it has nothing left to do: no window shown, no
    // job (a finished one is kept for a minute for its caller), for a few
    // seconds. Started at once, so a program nobody calls doesn't linger.
    QElapsedTimer busySince;
    busySince.start();
    QTimer idleCheck;
    idleCheck.setInterval(1000);
    QObject::connect(&idleCheck, &QTimer::timeout, &app, [&] {
        bool shown = jobs.hasWindows();
        for (QWindow *w : QGuiApplication::topLevelWindows()) {
            if (w->isVisible() && !w->flags().testFlag(Qt::ToolTip)) {
                shown = true;
            }
        }
        if (shown || !jobs.idle()) {
            busySince.restart();
        } else if (busySince.elapsed() > 5000) {
            QCoreApplication::quit();
        }
    });
    idleCheck.start();

    const int code = app.exec();
    // Jobs stop and take their staging folders away before the program ends.
    jobs.shutdown(15000);
    engine.reset();
    return code;
}

#include "main.moc"
