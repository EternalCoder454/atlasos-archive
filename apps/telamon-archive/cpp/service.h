// The job service as Qt objects: what the D-Bus job objects (archive1.cpp) and
// the job windows (qml/JobWindows.qml) both read. The logic is Rust's
// (src/ffi.rs over crates/telamon-archive-service); this only turns its JSON
// and events into properties, signals and calls.
#pragma once

#include <QAbstractListModel>
#include <QHash>
#include <QJsonObject>
#include <QAtomicPointer>
#include <QObject>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>
#include <QWindow>

class JobsService;
class JobItem;

// The jobs that have a window, as a model: a window is made when its row is
// added and goes when it is removed, and nothing else touches it (a list that
// is replaced would make every window again, and lose what is typed in them).
class JobWindowsModel : public QAbstractListModel
{
    Q_OBJECT
public:
    enum Roles { JobRole = Qt::UserRole + 1 };
    explicit JobWindowsModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    // Takes the rows to `want` (sorted by id): removes the others, appends the new.
    void sync(const QList<JobItem *> &want);

private:
    QList<JobItem *> m_list;
};

// One job, in the property names of the window's Backend (jobState, jobTitle,
// question...) so JobView.qml and Questions.qml show it unchanged.
class JobItem : public QObject
{
    Q_OBJECT
    Q_PROPERTY(uint id READ id CONSTANT)
    Q_PROPERTY(QString kind READ kind NOTIFY changed)
    Q_PROPERTY(QString jobState READ jobState NOTIFY changed)
    Q_PROPERTY(QString jobTitle READ jobTitle NOTIFY changed)
    Q_PROPERTY(QString jobText READ jobText NOTIFY changed)
    Q_PROPERTY(double jobFraction READ jobFraction NOTIFY changed)
    Q_PROPERTY(QString jobResult READ jobResult NOTIFY changed)
    Q_PROPERTY(QString jobResultShown READ jobResultShown NOTIFY changed)
    Q_PROPERTY(int jobLeft READ jobLeft NOTIFY changed)
    Q_PROPERTY(QString jobError READ jobError NOTIFY changed)
    Q_PROPERTY(QString jobDetails READ jobDetails NOTIFY changed)
    Q_PROPERTY(QString jobWarning READ jobWarning NOTIFY changed)
    Q_PROPERTY(QString jobQueue READ jobQueue NOTIFY changed)
    Q_PROPERTY(bool jobOnly READ jobOnly CONSTANT)
    Q_PROPERTY(QString question READ question NOTIFY changed)
    Q_PROPERTY(QString questionText READ questionText NOTIFY changed)
    Q_PROPERTY(bool questionWrong READ questionWrong NOTIFY changed)
    Q_PROPERTY(QString passwordNote READ passwordNote NOTIFY changed)
    // Beyond the Backend's names:
    Q_PROPERTY(bool paused READ paused NOTIFY changed)
    Q_PROPERTY(bool over READ over NOTIFY changed)
    Q_PROPERTY(QString dialog READ dialog NOTIFY changed)
    Q_PROPERTY(QStringList dialogSources READ dialogSources NOTIFY changed)
    Q_PROPERTY(QString dialogFolder READ dialogFolder NOTIFY changed)
    Q_PROPERTY(QString dialogName READ dialogName NOTIFY changed)
    Q_PROPERTY(QString dialogFormat READ dialogFormat NOTIFY changed)
    Q_PROPERTY(QString dialogError READ dialogError NOTIFY changed)

public:
    JobItem(uint id, JobsService *owner);

    uint id() const { return m_id; }
    QString kind() const { return m_json.value(QLatin1String("kind")).toString(); }
    QString jobState() const;
    QString jobTitle() const { return m_json.value(QLatin1String("title")).toString(); }
    QString jobText() const { return m_json.value(QLatin1String("text")).toString(); }
    double jobFraction() const;
    QString jobResult() const { return m_json.value(QLatin1String("resultPath")).toString(); }
    QString jobResultShown() const { return jobResult(); }
    int jobLeft() const;
    QString jobError() const { return m_json.value(QLatin1String("error")).toString(); }
    QString jobDetails() const;
    QString jobWarning() const { return m_json.value(QLatin1String("warning")).toString(); }
    QString jobQueue() const { return m_json.value(QLatin1String("queueNote")).toString(); }
    bool jobOnly() const { return false; }
    QString question() const;
    QString questionText() const;
    bool questionWrong() const { return m_json.value(QLatin1String("ask")).toObject().value(QLatin1String("wrong")).toBool(); }
    QString passwordNote() const { return m_note; }
    bool paused() const { return m_json.value(QLatin1String("state")).toString() == QLatin1String("paused"); }
    bool over() const;
    QString dialog() const { return m_json.value(QLatin1String("dialog")).toObject().value(QLatin1String("type")).toString(); }
    QStringList dialogSources() const;
    QString dialogFolder() const { return m_json.value(QLatin1String("dialog")).toObject().value(QLatin1String("folder")).toString(); }
    QString dialogName() const { return m_json.value(QLatin1String("dialog")).toObject().value(QLatin1String("name")).toString(); }
    QString dialogFormat() const { return m_json.value(QLatin1String("dialog")).toObject().value(QLatin1String("format")).toString(); }
    QString dialogError() const { return m_dialogError; }

    // The raw snapshot, for the D-Bus objects.
    const QJsonObject &json() const { return m_json; }
    bool showProgress() const { return m_json.value(QLatin1String("showProgress")).toBool(true); }
    QString token() const { return m_json.value(QLatin1String("token")).toString(); }
    QString parentWindow() const { return m_json.value(QLatin1String("parent")).toString(); }
    bool dismissed() const { return m_dismissed; }
    bool windowWanted() const { return m_windowWanted; }
    void wantWindow() { m_windowWanted = true; }
    // Takes a fresh snapshot; true if anything changed.
    bool refresh();

    // The window's calls.
    Q_INVOKABLE void cancelJob();
    Q_INVOKABLE void closeJob();
    Q_INVOKABLE void showFiles();
    Q_INVOKABLE void pauseJob();
    Q_INVOKABLE void resumeJob();
    Q_INVOKABLE void answerPassword(const QString &password);
    Q_INVOKABLE void cancelPassword();
    Q_INVOKABLE void answerLimit(bool goOn);
    // 0 Replace, 1 Skip, 2 Keep Both.
    Q_INVOKABLE void answerClash(int action, bool all);
    Q_INVOKABLE void confirmExtract(const QString &folder);
    Q_INVOKABLE void confirmCompress(const QString &folder, const QString &name, const QString &format, const QString &level);

    // The D-Bus side's calls (same job, other door).
    void pause();
    void resume();
    void cancel();
    bool answerConflict(const QString &action, bool all);
    bool answerLimitBus(bool goOn);

Q_SIGNALS:
    void changed();
    void showFilesRequested(const QString &path);
    void dismissedChanged();

private:
    friend class JobsService;
    uint m_id;
    JobsService *m_owner;
    QJsonObject m_json;
    QByteArray m_raw;
    QString m_note;
    QString m_dialogError;
    bool m_dismissed = false;
    bool m_windowWanted = false;
    // The service no longer has the job; the window is all that is left.
    bool m_orphan = false;
};

class JobsService : public QObject
{
    Q_OBJECT
    // The jobs that have a window open, for an Instantiator.
    Q_PROPERTY(QObject *windowModel READ windowModel CONSTANT)

public:
    explicit JobsService(QObject *parent = nullptr);
    ~JobsService() override;

    // Starts the Rust service; false if it was started already.
    bool start();
    QObject *windowModel() { return &m_model; }
    // The item of a finished job whose object the service forgot (its window was still open).
    void forget(JobItem *item);
    JobItem *item(uint id) const { return m_items.value(id); }
    bool idle() const;
    // Whether a window of a job is open (the app stays up for it).
    bool hasWindows() const;
    void shutdown(int ms);

    // The API: an id, or 0 with the error's name and words filled in.
    // `options` is the call's a{sv}.
    uint extractHere(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg);
    uint extractTo(const QStringList &archives, const QString &folder, const QVariantMap &options, QString *errName, QString *errMsg);
    uint extractAll(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg);
    uint extractEntries(const QString &archive, const QStringList &entries, const QString &folder, const QVariantMap &options, QString *errName, QString *errMsg);
    uint compress(const QStringList &files, const QString &format, const QString &destination, const QVariantMap &options, QString *errName, QString *errMsg);
    uint compressDialog(const QStringList &files, const QVariantMap &options, QString *errName, QString *errMsg);
    uint test(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg);
    // Checks the archive of an `Open`; the path, or "" with the error.
    QString open(const QString &archive, QString *errName, QString *errMsg);

    // Makes the Qt side of a job the call just made: the item and its D-Bus
    // objects. Called before the call returns.
    void adopt(uint id);

    // Puts the window `w` of `job` where the caller asked: over its window,
    // with its activation token.
    Q_INVOKABLE void prepareWindow(QWindow *w, JobItem *job);
    // Hands the caller's activation token to the window system for the window
    // about to appear.
    static void useToken(const QString &token);

    // Called from the Rust callback, on any thread.
    static void event(int kind, uint id, const char *arg);

Q_SIGNALS:
    void windowsChanged();
    void jobAdded(uint id);
    // The job's properties changed (for the D-Bus objects); `finished` once it is over.
    void jobChanged(uint id);
    void jobFinished(uint id, const QString &state, const QStringList &results);
    void jobRemoved(uint id);
    // A window of this job should come up (a question, or progress asked for).
    void needsWindow(uint id);
    // A finished job's folder should be shown in the file manager.
    void showFilesRequested(const QString &path);

private Q_SLOTS:
    void handle(int kind, uint id, const QByteArray &arg);

private:
    friend class JobItem;
    void update();

    QHash<uint, JobItem *> m_items;
    JobWindowsModel m_model;
    static QAtomicPointer<JobsService> s_instance;
};
