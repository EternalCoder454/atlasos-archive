import QtQuick
import QtQuick.Layouts
import QtQuick.Dialogs
import org.kde.kirigami as Kirigami
import Atlas.Ui

// Atlas Archive's window: the centred hero with nothing open, the archive as
// folders, or the job view; the questions a job asks are dialogs over any of
// them (docs/DESIGN.md, "Look").
AtlasWindow {
    id: root

    // The Rust backend (src/backend.rs); main.cpp sets it.
    required property var backend

    // The window shows only a job: it closes itself after a clean success.
    readonly property bool jobOnly: backend.jobOnly

    title: AtlasApp.name
    width: Kirigami.Units.gridUnit * 52
    height: Kirigami.Units.gridUnit * 34
    minimumWidth: Kirigami.Units.gridUnit * 24
    minimumHeight: Kirigami.Units.gridUnit * 18
    stateKey: "main"
    visible: true
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    // Closing the window cancels the job; the client removes its staging.
    onClosing: root.backend.cancelJob()

    // A file dropped on the window opens, unless a job is running.
    DropArea {
        anchors.fill: parent
        keys: ["text/uri-list"]
        enabled: root.backend.view !== "job"
        onDropped: drop => {
            if (drop.hasUrls && drop.urls.length > 0) {
                root.backend.openArchive(drop.urls[0].toString());
            }
        }
    }

    FileDialog {
        id: openDialog
        title: qsTr("Open Archive")
        fileMode: FileDialog.OpenFile
        nameFilters: [
            qsTr("Archives (*.zip *.7z *.rar *.tar *.tar.gz *.tgz *.tar.bz2 *.tar.xz *.tar.zst *.tar.lz4 *.gz *.bz2 *.xz *.zst *.lz4 *.cab *.cpio *.deb *.rpm *.jar *.iso)"),
            qsTr("All Files (*)")
        ]
        onAccepted: root.backend.openArchive(selectedFile.toString())
    }

    // After a clean success there is nothing to read: the window closes.
    // Skipped items, a warning or an error keep it open.
    function finishedClean(): bool {
        const b = root.backend;
        const d = JSON.parse(b.jobDetails || "{\"rows\":[],\"more\":0}");
        return b.jobState === "done" && b.jobError === "" && b.jobWarning === "" && d.rows.length === 0 && d.more === 0;
    }

    Connections {
        target: root.backend
        function onJobStateChanged() {
            if (root.backend.jobOnly && (root.backend.jobState === "cancelled" || root.finishedClean())) {
                Qt.quit();
            }
        }
    }

    InfoBanner {
        id: notice
        z: 2
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        type: "warning"
        text: root.backend.notice
        shown: root.backend.notice !== ""
        closable: true
    }

    // Nothing open.
    ColumnLayout {
        anchors.centerIn: parent
        visible: root.backend.view === ""
        width: Math.min(parent.width - Kirigami.Units.gridUnit * 4, Kirigami.Units.gridUnit * 28)
        spacing: Kirigami.Units.largeSpacing * 2

        StatusHero {
            Layout.alignment: Qt.AlignHCenter
            iconName: "package-x-generic"
            headline: qsTr("Open an Archive")
            subtitle: qsTr("Choose an archive to see what's inside, or drop one here.")
        }

        InfoBanner {
            Layout.fillWidth: true
            type: "error"
            text: root.backend.openError
            shown: root.backend.openError !== ""
        }

        PrimaryButton {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("Open Archive…")
            onClicked: openDialog.open()
        }
    }

    // Reading the listing.
    StatusHero {
        anchors.centerIn: parent
        visible: root.backend.view === "loading"
        iconName: "package-x-generic"
        busy: true
        headline: qsTr("Opening %1").arg(root.backend.archiveName)
        subtitle: qsTr("Reading what's inside…")
    }

    ArchiveView {
        anchors.fill: parent
        anchors.topMargin: notice.shown ? notice.height : 0
        visible: root.backend.view === "archive"
        backend: root.backend
        onOpenRequested: openDialog.open()
    }

    JobView {
        anchors.fill: parent
        anchors.topMargin: notice.shown ? notice.height : 0
        visible: root.backend.view === "job"
        backend: root.backend
    }

    Questions {
        backend: root.backend
    }
}
