#include "archive1.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QJsonArray>

namespace JobProps
{
QString title(const JobItem *j) { return j ? j->jobTitle() : QString(); }
QString state(const JobItem *j) { return j ? j->json().value(QLatin1String("state")).toString() : QStringLiteral("failed"); }
qulonglong processedBytes(const JobItem *j) { return j ? qulonglong(j->json().value(QLatin1String("processedBytes")).toDouble()) : 0; }
qulonglong totalBytes(const JobItem *j) { return j ? qulonglong(j->json().value(QLatin1String("totalBytes")).toDouble()) : 0; }
uint processedItems(const JobItem *j) { return j ? uint(j->json().value(QLatin1String("processedItems")).toDouble()) : 0; }
uint totalItems(const JobItem *j) { return j ? uint(j->json().value(QLatin1String("totalItems")).toDouble()) : 0; }
QString error(const JobItem *j) { return j ? j->jobError() : QString(); }
QString kind(const JobItem *j) { return j ? j->kind() : QString(); }
QString question(const JobItem *j)
{
    return j ? j->json().value(QLatin1String("ask")).toObject().value(QLatin1String("kind")).toString() : QString();
}
QString questionText(const JobItem *j)
{
    return j ? j->json().value(QLatin1String("ask")).toObject().value(QLatin1String("text")).toString() : QString();
}
QStringList results(const JobItem *j)
{
    QStringList out;
    if (j) {
        for (const QJsonValue &v : j->json().value(QLatin1String("results")).toArray()) {
            out << v.toString();
        }
    }
    return out;
}
QVariantMap all(const JobItem *j)
{
    QVariantMap m;
    m.insert(QStringLiteral("Title"), title(j));
    m.insert(QStringLiteral("State"), state(j));
    m.insert(QStringLiteral("ProcessedBytes"), processedBytes(j));
    m.insert(QStringLiteral("TotalBytes"), totalBytes(j));
    m.insert(QStringLiteral("ProcessedItems"), processedItems(j));
    m.insert(QStringLiteral("TotalItems"), totalItems(j));
    m.insert(QStringLiteral("Error"), error(j));
    m.insert(QStringLiteral("Kind"), kind(j));
    m.insert(QStringLiteral("Question"), question(j));
    m.insert(QStringLiteral("QuestionText"), questionText(j));
    m.insert(QStringLiteral("Results"), results(j));
    return m;
}
}

// A job's two objects (one per name) and what was last said about it.
struct Archive1Core::Objects {
    TelamonJobObject *telamon = nullptr;
    AtlasJobObject *atlas = nullptr;
    QVariantMap last;
    bool dirty = false;
    bool registeredAtlas = false;
};

Archive1Core::Archive1Core(JobsService *service, QObject *parent)
    : QObject(parent)
    , m_service(service)
{
    connect(service, &JobsService::jobAdded, this, &Archive1Core::onAdded, Qt::DirectConnection);
    connect(service, &JobsService::jobChanged, this, &Archive1Core::onChanged);
    connect(service, &JobsService::jobFinished, this, &Archive1Core::onFinished);
    connect(service, &JobsService::jobRemoved, this, &Archive1Core::onRemoved);
    // PropertiesChanged at most ten times a second per job.
    m_flush.setInterval(100);
    connect(&m_flush, &QTimer::timeout, this, &Archive1Core::flush);
}

QString Archive1Core::pathFor(uint id, int flavor)
{
    return (flavor == 0 ? QStringLiteral("/net/eterneon/telamon/archive/job/%1") : QStringLiteral("/net/eterneon/atlas/archive/job/%1")).arg(id);
}

uint Archive1Core::adopted(uint id)
{
    if (id != 0) {
        m_service->adopt(id);
    }
    return id;
}

uint Archive1Core::extractHere(const QStringList &a, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->extractHere(a, o, n, m));
}
uint Archive1Core::extractTo(const QStringList &a, const QString &f, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->extractTo(a, f, o, n, m));
}
uint Archive1Core::extractAll(const QStringList &a, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->extractAll(a, o, n, m));
}
uint Archive1Core::extractEntries(const QString &a, const QStringList &e, const QString &f, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->extractEntries(a, e, f, o, n, m));
}
uint Archive1Core::compress(const QStringList &files, const QString &format, const QString &dest, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->compress(files, format, dest, o, n, m));
}
uint Archive1Core::compressDialog(const QStringList &files, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->compressDialog(files, o, n, m));
}
uint Archive1Core::test(const QStringList &a, const QVariantMap &o, QString *n, QString *m)
{
    return adopted(m_service->test(a, o, n, m));
}

bool Archive1Core::open(const QString &archive, const QVariantMap &o, QString *n, QString *m)
{
    const QString path = m_service->open(archive, n, m);
    if (path.isEmpty()) {
        return false;
    }
    Q_EMIT openRequested(path, o.value(QStringLiteral("activation_token")).toString(), o.value(QStringLiteral("parent_window")).toString());
    return true;
}

void Archive1Core::onAdded(uint id)
{
    JobItem *item = m_service->item(id);
    if (!item || m_objects.contains(id)) {
        return;
    }
    auto *o = new Objects;
    o->telamon = new TelamonJobObject(item);
    o->atlas = new AtlasJobObject(item);
    o->telamon->setParent(this);
    o->atlas->setParent(this);
    QDBusConnection bus = QDBusConnection::sessionBus();
    const auto flags = QDBusConnection::ExportAllProperties | QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllSignals;
    if (!bus.registerObject(pathFor(id, 0), o->telamon, flags)) {
        qWarning("telamon-archive: could not serve job %u", id);
    }
    // The old name's object exists only if the old name is ours.
    o->registeredAtlas = bus.registerObject(pathFor(id, 1), o->atlas, flags);
    o->last = JobProps::all(item);
    m_objects.insert(id, o);
}

void Archive1Core::sendChanges(uint id)
{
    Objects *o = m_objects.value(id);
    JobItem *item = m_service->item(id);
    if (!o || !item) {
        return;
    }
    const QVariantMap now = JobProps::all(item);
    QVariantMap changed;
    for (auto it = now.cbegin(); it != now.cend(); ++it) {
        if (o->last.value(it.key()) != it.value()) {
            changed.insert(it.key(), it.value());
        }
    }
    o->last = now;
    o->dirty = false;
    if (changed.isEmpty()) {
        return;
    }
    QDBusConnection bus = QDBusConnection::sessionBus();
    for (int flavor = 0; flavor < 2; ++flavor) {
        if (flavor == 1 && !o->registeredAtlas) {
            continue;
        }
        QDBusMessage m = QDBusMessage::createSignal(pathFor(id, flavor), QStringLiteral("org.freedesktop.DBus.Properties"), QStringLiteral("PropertiesChanged"));
        m << QString::fromLatin1(flavor == 0 ? "net.eterneon.telamon.Archive1.Job" : "net.eterneon.atlas.Archive1.Job") << changed << QStringList();
        bus.send(m);
    }
}

void Archive1Core::onChanged(uint id)
{
    Objects *o = m_objects.value(id);
    if (!o) {
        return;
    }
    o->dirty = true;
    if (!m_flush.isActive()) {
        m_flush.start();
    }
}

void Archive1Core::flush()
{
    bool more = false;
    for (auto it = m_objects.cbegin(); it != m_objects.cend(); ++it) {
        if (it.value()->dirty) {
            sendChanges(it.key());
            more = true;
        }
    }
    if (!more) {
        m_flush.stop();
    }
}

void Archive1Core::onFinished(uint id, const QString &state, const QStringList &results)
{
    Objects *o = m_objects.value(id);
    if (!o) {
        return;
    }
    // The last property changes go out before the signal that ends the job.
    sendChanges(id);
    Q_EMIT o->telamon->Finished(state, results);
    if (o->registeredAtlas) {
        Q_EMIT o->atlas->Finished(state, results);
    }
}

void Archive1Core::onRemoved(uint id)
{
    Objects *o = m_objects.take(id);
    if (!o) {
        return;
    }
    QDBusConnection bus = QDBusConnection::sessionBus();
    bus.unregisterObject(pathFor(id, 0));
    bus.unregisterObject(pathFor(id, 1));
    delete o->telamon;
    delete o->atlas;
    delete o;
}
