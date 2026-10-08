// net.eterneon.telamon.Archive1 on the session bus (docs/DESIGN.md, "The API
// other apps call"), and the same interface as net.eterneon.atlas.Archive1 for
// the release that keeps the old names. The methods hang off the objects
// KDBusService (and the legacy Application object) already export; each job
// is an object of its own, in both names. The work is the job service's
// (service.h); this is the bus.
#pragma once

#include <QDBusAbstractAdaptor>
#include <QDBusConnection>
#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QHash>
#include <QPointer>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>

#include "service.h"

// What one name of the API is: its D-Bus names and paths.
struct ApiNames {
    const char *interface;
    const char *jobInterface;
    const char *errorPrefix;
    const char *jobPathPrefix;
};

class Archive1Core : public QObject
{
    Q_OBJECT
public:
    explicit Archive1Core(JobsService *service, QObject *parent = nullptr);

    // The methods; each returns the job's id, or 0 with the error filled in.
    uint extractHere(const QStringList &archives, const QVariantMap &o, QString *n, QString *m);
    uint extractTo(const QStringList &archives, const QString &folder, const QVariantMap &o, QString *n, QString *m);
    uint extractAll(const QStringList &archives, const QVariantMap &o, QString *n, QString *m);
    uint extractEntries(const QString &archive, const QStringList &entries, const QString &folder, const QVariantMap &o, QString *n, QString *m);
    uint compress(const QStringList &files, const QString &format, const QString &dest, const QVariantMap &o, QString *n, QString *m);
    uint compressDialog(const QStringList &files, const QVariantMap &o, QString *n, QString *m);
    uint test(const QStringList &archives, const QVariantMap &o, QString *n, QString *m);
    bool open(const QString &archive, const QVariantMap &o, QString *n, QString *m);

    // The path of a job's object in one of the two names (0 telamon, 1 atlas).
    static QString pathFor(uint id, int flavor);
    JobsService *service() const { return m_service; }

Q_SIGNALS:
    void openRequested(const QString &path, const QString &token, const QString &parentWindow);

private Q_SLOTS:
    void onAdded(uint id);
    void onChanged(uint id);
    void onFinished(uint id, const QString &state, const QStringList &results);
    void onRemoved(uint id);
    void flush();

private:
    struct Objects;
    uint adopted(uint id);
    void sendChanges(uint id);

    JobsService *m_service;
    QHash<uint, Objects *> m_objects;
    QTimer m_flush;
};

// The properties both flavours of a job object show, read off the job.
namespace JobProps
{
QString title(const JobItem *j);
QString state(const JobItem *j);
qulonglong processedBytes(const JobItem *j);
qulonglong totalBytes(const JobItem *j);
uint processedItems(const JobItem *j);
uint totalItems(const JobItem *j);
QString error(const JobItem *j);
QString kind(const JobItem *j);
QString question(const JobItem *j);
QString questionText(const JobItem *j);
QStringList results(const JobItem *j);
QVariantMap all(const JobItem *j);
}

// Each flavour is one class with its interface name; the macro keeps the two
// in step.
#define ARCHIVE_JOB_CLASS(Name, Interface, ErrorPrefix)                                                                   \
    class Name : public QObject, public QDBusContext                                                                   \
    {                                                                                                                     \
        Q_OBJECT                                                                                                          \
        Q_CLASSINFO("D-Bus Interface", Interface)                                                                         \
        Q_PROPERTY(QString Title READ Title)                                                                              \
        Q_PROPERTY(QString State READ State)                                                                              \
        Q_PROPERTY(qulonglong ProcessedBytes READ ProcessedBytes)                                                         \
        Q_PROPERTY(qulonglong TotalBytes READ TotalBytes)                                                                 \
        Q_PROPERTY(uint ProcessedItems READ ProcessedItems)                                                               \
        Q_PROPERTY(uint TotalItems READ TotalItems)                                                                       \
        Q_PROPERTY(QString Error READ Error)                                                                              \
        Q_PROPERTY(QString Kind READ Kind)                                                                                \
        Q_PROPERTY(QString Question READ Question)                                                                        \
        Q_PROPERTY(QString QuestionText READ QuestionText)                                                                \
        Q_PROPERTY(QStringList Results READ Results)                                                                      \
    public:                                                                                                               \
        explicit Name(JobItem *job)                                                                                       \
            : m_job(job)                                                                                                  \
        {                                                                                                                 \
        }                                                                                                                 \
        QString Title() const { return JobProps::title(m_job); }                                                          \
        QString State() const { return JobProps::state(m_job); }                                                          \
        qulonglong ProcessedBytes() const { return JobProps::processedBytes(m_job); }                                     \
        qulonglong TotalBytes() const { return JobProps::totalBytes(m_job); }                                             \
        uint ProcessedItems() const { return JobProps::processedItems(m_job); }                                           \
        uint TotalItems() const { return JobProps::totalItems(m_job); }                                                   \
        QString Error() const { return JobProps::error(m_job); }                                                          \
        QString Kind() const { return JobProps::kind(m_job); }                                                            \
        QString Question() const { return JobProps::question(m_job); }                                                    \
        QString QuestionText() const { return JobProps::questionText(m_job); }                                            \
        QStringList Results() const { return JobProps::results(m_job); }                                                  \
    public Q_SLOTS:                                                                                                       \
        void Pause() { m_job->pause(); }                                                                                  \
        void Resume() { m_job->resume(); }                                                                                \
        void Cancel() { m_job->cancel(); }                                                                                \
        bool AnswerConflict(const QString &action, bool all)                                                              \
        {                                                                                                                 \
            if (action != QLatin1String("replace") && action != QLatin1String("skip") && action != QLatin1String("keep-both")) { \
                sendErrorReply(QStringLiteral(ErrorPrefix "InvalidArgs"), QStringLiteral("The answer must be replace, skip or keep-both.")); \
                return false;                                                                                             \
            }                                                                                                             \
            return m_job->answerConflict(action, all);                                                                    \
        }                                                                                                                 \
        bool AnswerLimit(bool goOn) { return m_job->answerLimitBus(goOn); }                                               \
    Q_SIGNALS:                                                                                                            \
        void Finished(const QString &state, const QStringList &results);                                                  \
    private:                                                                                                              \
        QPointer<JobItem> m_job;                                                                                          \
    };

ARCHIVE_JOB_CLASS(TelamonJobObject, "net.eterneon.telamon.Archive1.Job", "net.eterneon.telamon.Archive1.Error.")
ARCHIVE_JOB_CLASS(AtlasJobObject, "net.eterneon.atlas.Archive1.Job", "net.eterneon.atlas.Archive1.Error.")

#define ARCHIVE_ADAPTOR_CLASS(Name, Interface, ErrorPrefix, Flavor)                                                       \
    class Name : public QDBusAbstractAdaptor                                                      \
    {                                                                                                                     \
        Q_OBJECT                                                                                                          \
        Q_CLASSINFO("D-Bus Interface", Interface)                                                                         \
    public:                                                                                                               \
        Name(QObject *parent, Archive1Core *core)                                                                         \
            : QDBusAbstractAdaptor(parent)                                                                                \
            , m_core(core)                                                                                                \
        {                                                                                                                 \
            setAutoRelaySignals(false);                                                                                   \
        }                                                                                                                 \
    public Q_SLOTS:                                                                                                       \
        QDBusObjectPath ExtractHere(const QStringList &archives, const QVariantMap &options, const QDBusMessage &message)                              \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->extractHere(archives, options, &n, &m), n, m);                                           \
        }                                                                                                                 \
        QDBusObjectPath ExtractTo(const QStringList &archives, const QString &folder, const QVariantMap &options, const QDBusMessage &message)         \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->extractTo(archives, folder, options, &n, &m), n, m);                                     \
        }                                                                                                                 \
        QDBusObjectPath ExtractAll(const QStringList &archives, const QVariantMap &options, const QDBusMessage &message)                               \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->extractAll(archives, options, &n, &m), n, m);                                            \
        }                                                                                                                 \
        QDBusObjectPath ExtractEntries(const QString &archive, const QStringList &entries, const QString &folder, const QVariantMap &options, const QDBusMessage &message) \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->extractEntries(archive, entries, folder, options, &n, &m), n, m);                        \
        }                                                                                                                 \
        QDBusObjectPath Compress(const QStringList &files, const QString &format, const QString &destination, const QVariantMap &options, const QDBusMessage &message) \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->compress(files, format, destination, options, &n, &m), n, m);                            \
        }                                                                                                                 \
        QDBusObjectPath CompressDialog(const QStringList &files, const QVariantMap &options, const QDBusMessage &message)                              \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->compressDialog(files, options, &n, &m), n, m);                                           \
        }                                                                                                                 \
        QDBusObjectPath Test(const QStringList &archives, const QVariantMap &options, const QDBusMessage &message)                                     \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            return reply(message, m_core->test(archives, options, &n, &m), n, m);                                                  \
        }                                                                                                                 \
        void Open(const QString &archive, const QVariantMap &options, const QDBusMessage &message)                                                     \
        {                                                                                                                 \
            QString n, m;                                                                                                 \
            if (!m_core->open(archive, options, &n, &m)) {                                                                \
                fail(message, QStringLiteral(ErrorPrefix) + n, m);                                                       \
            }                                                                                                             \
        }                                                                                                                 \
    private:                                                                                                              \
        QDBusObjectPath reply(const QDBusMessage &message, uint id, const QString &n, const QString &m)                                                \
        {                                                                                                                 \
            if (id == 0) {                                                                                                \
                fail(message, QStringLiteral(ErrorPrefix) + n, m);                                                        \
                return QDBusObjectPath();                                                                                 \
            }                                                                                                             \
            return QDBusObjectPath(Archive1Core::pathFor(id, Flavor));                                                    \
        }                                                                                                                 \
        static void fail(const QDBusMessage &message, const QString &name, const QString &text)                           \
        {                                                                                                                 \
            message.setDelayedReply(true);                                                                                \
            QDBusConnection::sessionBus().send(message.createErrorReply(name, text));                                     \
        }                                                                                                                 \
        Archive1Core *m_core;                                                                                             \
    };

ARCHIVE_ADAPTOR_CLASS(TelamonArchive1Adaptor, "net.eterneon.telamon.Archive1", "net.eterneon.telamon.Archive1.Error.", 0)
ARCHIVE_ADAPTOR_CLASS(AtlasArchive1Adaptor, "net.eterneon.atlas.Archive1", "net.eterneon.atlas.Archive1.Error.", 1)
