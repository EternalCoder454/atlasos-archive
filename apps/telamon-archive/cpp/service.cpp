#include "service.h"

#include "ffi.h"

#include <KWindowSystem>

#include <QCoreApplication>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QUrl>

#include <algorithm>
#include <cstring>

QAtomicPointer<JobsService> JobsService::s_instance = nullptr;

namespace
{
// UTF-8 copies of a list of strings, as the C interface wants them.
struct CList {
    explicit CList(const QStringList &list)
    {
        bytes.reserve(list.size());
        ptrs.reserve(list.size());
        for (const QString &s : list) {
            bytes.append(s.toUtf8());
        }
        for (const QByteArray &b : std::as_const(bytes)) {
            ptrs.append(b.constData());
        }
    }
    const char *const *data() const { return ptrs.constData(); }
    size_t size() const { return size_t(ptrs.size()); }

    QList<QByteArray> bytes;
    QList<const char *> ptrs;
};

// The a{sv} of a call, as the options the service takes.
struct CallOpts {
    explicit CallOpts(const QVariantMap &m)
        : token(m.value(QStringLiteral("activation_token")).toString().toUtf8())
        , parent(m.value(QStringLiteral("parent_window")).toString().toUtf8())
    {
        const QVariant sp = m.value(QStringLiteral("show_progress"), true);
        o.show_progress = sp.toBool() ? 1 : 0;
        o.activation_token = token.isEmpty() ? nullptr : token.constData();
        o.parent_window = parent.isEmpty() ? nullptr : parent.constData();
    }
    TaCallOptions o{};
    QByteArray token;
    QByteArray parent;
};

QString takeString(char *s)
{
    if (!s) {
        return {};
    }
    const QString out = QString::fromUtf8(s);
    telamon_string_free(s);
    return out;
}

// A folder from a QML dialog: a file: URL or a path.
QString localPath(const QString &text)
{
    if (text.startsWith(QLatin1String("file:"))) {
        return QUrl(text).toLocalFile();
    }
    return text;
}

QString errorName(int kind)
{
    return kind == TaTooManyJobs ? QStringLiteral("TooManyJobs") : QStringLiteral("InvalidArgs");
}

// Binds and runs one C call; `f` gets the out-parameters.
template<typename F>
uint run(QString *errName, QString *errMsg, F &&f)
{
    int kind = 0;
    char *msg = nullptr;
    const uint id = f(&kind, &msg);
    const QString text = takeString(msg);
    if (id == 0) {
        if (errName) {
            *errName = errorName(kind);
        }
        if (errMsg) {
            *errMsg = text.isEmpty() ? QStringLiteral("Telamon Archive couldn't use that request.") : text;
        }
    }
    return id;
}
}

// ---- JobItem ----

JobItem::JobItem(uint id, JobsService *owner)
    : QObject(owner)
    , m_id(id)
    , m_owner(owner)
{
}

bool JobItem::refresh()
{
    char *s = telamon_service_snapshot(m_id);
    if (!s) {
        return false;
    }
    const QByteArray raw(s);
    telamon_string_free(s);
    if (raw == m_raw) {
        return false;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(raw);
    if (!doc.isObject()) {
        return false;
    }
    m_raw = raw;
    m_json = doc.object();
    Q_EMIT changed();
    return true;
}

QString JobItem::jobState() const
{
    const QString s = m_json.value(QLatin1String("state")).toString();
    if (s == QLatin1String("done") || s == QLatin1String("failed") || s == QLatin1String("cancelled")) {
        return s;
    }
    return QStringLiteral("running");
}

bool JobItem::over() const
{
    const QString s = jobState();
    return s != QLatin1String("running");
}

double JobItem::jobFraction() const
{
    if (jobState() == QLatin1String("done")) {
        return 1.0;
    }
    const double total = m_json.value(QLatin1String("totalBytes")).toDouble();
    if (total <= 0) {
        // Items, for a job that counts only those.
        const double items = m_json.value(QLatin1String("totalItems")).toDouble();
        if (items > 0) {
            return std::clamp(m_json.value(QLatin1String("processedItems")).toDouble() / items, 0.0, 1.0);
        }
        return -1.0;
    }
    return std::clamp(m_json.value(QLatin1String("processedBytes")).toDouble() / total, 0.0, 1.0);
}

int JobItem::jobLeft() const
{
    const qint64 n = m_json.value(QLatin1String("details")).toArray().size() + qint64(m_json.value(QLatin1String("detailsMore")).toDouble());
    return int(std::min<qint64>(n, INT_MAX));
}

QString JobItem::jobDetails() const
{
    QJsonObject o;
    o.insert(QStringLiteral("rows"), m_json.value(QLatin1String("details")).toArray());
    o.insert(QStringLiteral("more"), m_json.value(QLatin1String("detailsMore")).toDouble());
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

QString JobItem::question() const
{
    const QString k = m_json.value(QLatin1String("ask")).toObject().value(QLatin1String("kind")).toString();
    if (k == QLatin1String("conflict")) {
        return QStringLiteral("clash");
    }
    if (k == QLatin1String("password") || k == QLatin1String("limit")) {
        return k;
    }
    return {};
}

QString JobItem::questionText() const
{
    const QJsonObject ask = m_json.value(QLatin1String("ask")).toObject();
    if (ask.value(QLatin1String("kind")).toString() == QLatin1String("conflict")) {
        return ask.value(QLatin1String("item")).toString();
    }
    return ask.value(QLatin1String("text")).toString();
}

QStringList JobItem::dialogSources() const
{
    const QJsonObject d = m_json.value(QLatin1String("dialog")).toObject();
    QStringList out;
    const QJsonArray a = d.contains(QLatin1String("sources")) ? d.value(QLatin1String("sources")).toArray() : d.value(QLatin1String("archives")).toArray();
    for (const QJsonValue &v : a) {
        out << v.toString();
    }
    return out;
}

void JobItem::cancelJob()
{
    telamon_service_cancel(m_id);
    if (over()) {
        closeJob();
    }
}

void JobItem::closeJob()
{
    if (!over()) {
        telamon_service_cancel(m_id);
    }
    if (!m_dismissed) {
        m_dismissed = true;
        Q_EMIT dismissedChanged();
        m_owner->update();
        if (m_orphan) {
            m_owner->forget(this);
        }
    }
}

void JobItem::showFiles()
{
    const QString path = jobResult();
    if (path.startsWith(QLatin1Char('/'))) {
        Q_EMIT m_owner->showFilesRequested(path);
    }
}

void JobItem::pauseJob()
{
    telamon_service_pause(m_id);
}

void JobItem::resumeJob()
{
    telamon_service_resume(m_id);
}

void JobItem::answerPassword(const QString &password)
{
    QByteArray bytes = password.toUtf8();
    if (bytes.isEmpty() || bytes.size() > 64 * 1024) {
        m_note = bytes.isEmpty() ? tr("Type the password first.") : tr("That password is too long.");
        Q_EMIT changed();
        std::memset(bytes.data(), 0, size_t(bytes.size()));
        return;
    }
    m_note.clear();
    telamon_service_answer_password(m_id, reinterpret_cast<const unsigned char *>(bytes.constData()), size_t(bytes.size()));
    // Our copy of the text is wiped; Rust took its own.
    std::memset(bytes.data(), 0, size_t(bytes.size()));
}

void JobItem::cancelPassword()
{
    telamon_service_answer_password(m_id, nullptr, 0);
}

void JobItem::answerLimit(bool goOn)
{
    telamon_service_answer_limit(m_id, goOn ? 1 : 0);
}

void JobItem::answerClash(int action, bool all)
{
    const char *a = action == 0 ? "replace" : action == 1 ? "skip" : "keep-both";
    telamon_service_answer_conflict(m_id, a, all ? 1 : 0);
}

void JobItem::confirmExtract(const QString &folder)
{
    char *msg = nullptr;
    const QByteArray f = localPath(folder).toUtf8();
    if (!telamon_service_confirm_extract(m_id, f.constData(), &msg)) {
        m_dialogError = takeString(msg);
        Q_EMIT changed();
    } else {
        m_dialogError.clear();
    }
}

void JobItem::confirmCompress(const QString &folder, const QString &name, const QString &format, const QString &level)
{
    char *msg = nullptr;
    const QByteArray f = localPath(folder).toUtf8(), n = name.toUtf8(), fmt = format.toUtf8(), lv = level.toUtf8();
    if (!telamon_service_confirm_compress(m_id, f.constData(), n.constData(), fmt.constData(), lv.constData(), &msg)) {
        m_dialogError = takeString(msg);
        Q_EMIT changed();
    } else {
        m_dialogError.clear();
    }
}

void JobItem::pause()
{
    telamon_service_pause(m_id);
}

void JobItem::resume()
{
    telamon_service_resume(m_id);
}

void JobItem::cancel()
{
    telamon_service_cancel(m_id);
}

bool JobItem::answerConflict(const QString &action, bool all)
{
    return telamon_service_answer_conflict(m_id, action.toUtf8().constData(), all ? 1 : 0) != 0;
}

bool JobItem::answerLimitBus(bool goOn)
{
    return telamon_service_answer_limit(m_id, goOn ? 1 : 0) != 0;
}

// ---- JobsService ----

JobsService::JobsService(QObject *parent)
    : QObject(parent)
{
    s_instance.storeRelease(this);
}

JobsService::~JobsService()
{
    // Events that come now are dropped.
    s_instance.storeRelease(nullptr);
}

bool JobsService::start()
{
    return telamon_service_start(&JobsService::event) != 0;
}

void JobsService::event(int kind, uint id, const char *arg)
{
    JobsService *self = s_instance.loadAcquire();
    if (!self) {
        return;
    }
    QMetaObject::invokeMethod(self, "handle", Qt::QueuedConnection, Q_ARG(int, kind), Q_ARG(uint, id), Q_ARG(QByteArray, arg ? QByteArray(arg) : QByteArray()));
}

// ---- JobWindowsModel ----

JobWindowsModel::JobWindowsModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int JobWindowsModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : int(m_list.size());
}

QVariant JobWindowsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_list.size() || role != JobRole) {
        return {};
    }
    return QVariant::fromValue(m_list.at(index.row()));
}

QHash<int, QByteArray> JobWindowsModel::roleNames() const
{
    return {{JobRole, "job"}};
}

void JobWindowsModel::sync(const QList<JobItem *> &want)
{
    for (int i = int(m_list.size()) - 1; i >= 0; --i) {
        if (!want.contains(m_list.at(i))) {
            beginRemoveRows({}, i, i);
            m_list.removeAt(i);
            endRemoveRows();
        }
    }
    for (JobItem *it : want) {
        if (!m_list.contains(it)) {
            beginInsertRows({}, int(m_list.size()), int(m_list.size()));
            m_list.append(it);
            endInsertRows();
        }
    }
}

bool JobsService::hasWindows() const
{
    return std::any_of(m_items.cbegin(), m_items.cend(), [](JobItem *it) { return it->windowWanted() && !it->dismissed(); });
}

bool JobsService::idle() const
{
    return telamon_service_is_idle() != 0 && m_items.isEmpty();
}

void JobsService::shutdown(int ms)
{
    telamon_service_shutdown(uint32_t(ms));
}

void JobsService::update()
{
    QList<JobItem *> want;
    for (JobItem *it : std::as_const(m_items)) {
        if (it->windowWanted() && !it->dismissed()) {
            want << it;
        }
    }
    std::sort(want.begin(), want.end(), [](JobItem *a, JobItem *b) { return a->id() < b->id(); });
    m_model.sync(want);
    Q_EMIT windowsChanged();
}

void JobsService::forget(JobItem *item)
{
    if (m_items.value(item->id()) == item) {
        m_items.remove(item->id());
    }
    update();
    item->deleteLater();
}

void JobsService::useToken(const QString &token)
{
    if (!token.isEmpty()) {
        KWindowSystem::setCurrentXdgActivationToken(token);
    }
}

void JobsService::adopt(uint id)
{
    if (m_items.contains(id)) {
        return;
    }
    auto *it = new JobItem(id, this);
    m_items.insert(id, it);
    it->refresh();
    const bool asks = !it->json().value(QLatin1String("ask")).isNull();
    if (it->showProgress() || asks) {
        it->wantWindow();
    }
    Q_EMIT jobAdded(id);
    if (it->windowWanted()) {
        useToken(it->token());
        Q_EMIT needsWindow(id);
        update();
    }
}

void JobsService::handle(int kind, uint id, const QByteArray &arg)
{
    JobItem *it = m_items.value(id);
    switch (kind) {
    case TaChanged:
        if (it && it->refresh()) {
            Q_EMIT jobChanged(id);
        }
        break;
    case TaFinished: {
        if (!it) {
            break;
        }
        it->refresh();
        Q_EMIT jobChanged(id);
        const QJsonObject o = QJsonDocument::fromJson(arg).object();
        QStringList results;
        for (const QJsonValue &v : o.value(QLatin1String("results")).toArray()) {
            results << v.toString();
        }
        Q_EMIT jobFinished(id, o.value(QLatin1String("state")).toString(), results);
        // A clean success or a cancel closes its window by itself; a failure,
        // skipped items, a warning, and a test's result stay for the reader.
        const QString state = o.value(QLatin1String("state")).toString();
        const bool clean = state == QLatin1String("done") && it->jobError().isEmpty() && it->jobWarning().isEmpty() && it->jobLeft() == 0 && it->kind() != QLatin1String("test");
        if (clean || state == QLatin1String("cancelled")) {
            QTimer::singleShot(clean ? 600 : 0, it, [it] { it->closeJob(); });
        }
        break;
    }
    case TaNeedsUser:
        if (it) {
            it->refresh();
            // A question brings its window back even if it was closed.
            it->m_dismissed = false;
            it->wantWindow();
            useToken(it->token());
            Q_EMIT needsWindow(id);
            update();
        }
        break;
    case TaRemoved:
        if (it) {
            // The D-Bus objects go; a window still showing the result stays
            // until it is closed.
            Q_EMIT jobRemoved(id);
            if (it->windowWanted() && !it->dismissed()) {
                it->m_orphan = true;
            } else {
                m_items.remove(id);
                it->deleteLater();
                update();
            }
        }
        break;
    default:
        break;
    }
}

void JobsService::prepareWindow(QWindow *w, JobItem *job)
{
    if (!w || !job) {
        return;
    }
    const QString parent = job->parentWindow();
    if (parent.startsWith(QLatin1String("x11:")) && QGuiApplication::platformName() == QLatin1String("xcb")) {
        bool ok = false;
        const WId id = parent.mid(4).toULongLong(&ok, 16);
        if (ok && id != 0) {
            // WM_TRANSIENT_FOR, set on the window that exists: Qt's own
            // transient parent logic keeps a window with a foreign parent
            // from showing at all.
            KWindowSystem::setMainWindow(w, id);
        }
    } else if (parent.startsWith(QLatin1String("wayland:"))) {
        // The xdg-foreign handle of the caller's window.
        KWindowSystem::setMainWindow(w, parent.mid(8));
    }
}

// ---- the API ----

uint JobsService::extractHere(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(archives);
    const CallOpts o(options);
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_extract_here(l.data(), l.size(), &o.o, k, m); });
}

uint JobsService::extractTo(const QStringList &archives, const QString &folder, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(archives);
    const CallOpts o(options);
    const QByteArray f = folder.toUtf8();
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_extract_to(l.data(), l.size(), f.constData(), &o.o, k, m); });
}

uint JobsService::extractAll(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(archives);
    const CallOpts o(options);
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_extract_all(l.data(), l.size(), &o.o, k, m); });
}

uint JobsService::extractEntries(const QString &archive, const QStringList &entries, const QString &folder, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(entries);
    const CallOpts o(options);
    const QByteArray a = archive.toUtf8(), f = folder.toUtf8();
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_extract_entries(a.constData(), l.data(), l.size(), f.constData(), &o.o, k, m); });
}

uint JobsService::compress(const QStringList &files, const QString &format, const QString &destination, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(files);
    const CallOpts o(options);
    const QByteArray fmt = format.toUtf8(), d = destination.toUtf8();
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_compress(l.data(), l.size(), fmt.constData(), d.constData(), &o.o, k, m); });
}

uint JobsService::compressDialog(const QStringList &files, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(files);
    const CallOpts o(options);
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_compress_dialog(l.data(), l.size(), &o.o, k, m); });
}

uint JobsService::test(const QStringList &archives, const QVariantMap &options, QString *errName, QString *errMsg)
{
    const CList l(archives);
    const CallOpts o(options);
    return run(errName, errMsg, [&](int *k, char **m) { return telamon_service_test(l.data(), l.size(), &o.o, k, m); });
}

QString JobsService::open(const QString &archive, QString *errName, QString *errMsg)
{
    const QByteArray a = archive.toUtf8();
    char *path = nullptr, *msg = nullptr;
    int kind = 0;
    const int ok = telamon_service_open(a.constData(), &path, &kind, &msg);
    const QString p = takeString(path), m = takeString(msg);
    if (!ok) {
        if (errName) {
            *errName = errorName(kind);
        }
        if (errMsg) {
            *errMsg = m;
        }
        return {};
    }
    return p;
}
