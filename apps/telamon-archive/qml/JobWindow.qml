import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Telamon.Ui

// A job's window (docs/DESIGN.md, "Look"): the Extract All and Compress
// dialogs while they wait for a choice, then the job with Cancel (and Pause),
// then its result. Closing it before the job is over cancels the job.
TelamonWindow {
    id: win

    // The JobItem (cpp/service.cpp) and the JobsService.
    required property var job
    required property var service

    readonly property bool extractDialog: win.job.dialog === "extract"
    readonly property bool compressDialog: win.job.dialog === "compress"
    readonly property string kind: win.job.kind
    readonly property var formats: ["zip", "7z", "tar.gz", "tar.xz", "tar.zst"]
    readonly property var levels: ["store", "fast", "normal", "best"]

    title: win.job.jobTitle
    width: Kirigami.Units.gridUnit * (win.extractDialog || win.compressDialog ? 30 : 36)
    height: Kirigami.Units.gridUnit * (win.compressDialog ? 26 : win.extractDialog ? 18 : 22)
    minimumWidth: Kirigami.Units.gridUnit * 24
    minimumHeight: Kirigami.Units.gridUnit * 14
    visible: false
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    Component.onCompleted: {
        // The window shows, then goes over the caller's window (which the
        // window system wants of a window that exists), and takes the focus
        // with the activation token it was given.
        win.visible = true;
        win.service.prepareWindow(win, win.job);
        win.raise();
        win.requestActivate();
    }

    onClosing: close => {
        close.accepted = true;
        win.job.closeJob();
    }

    // A question brings the window to the front again.
    Connections {
        target: win.job
        function onChanged() {
            if (win.job.question !== "" && !win.active) {
                win.raise();
                win.requestActivate();
            }
        }
    }

    function names(list: var): string {
        const parts = list.map(p => p.split("/").filter(x => x !== "").pop() || p);
        return parts.length > 3 ? qsTr("%1, %2 and %3 more").arg(parts[0]).arg(parts[1]).arg(parts.length - 2) : parts.join(", ");
    }

    // Extract All…
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.gridUnit * 1.5
        spacing: Kirigami.Units.largeSpacing
        visible: win.extractDialog

        TelamonLabel {
            Layout.fillWidth: true
            textStyle: TelamonLabel.Title
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: qsTr("Extract All")
        }
        TelamonLabel {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: qsTr("%1 will be extracted into a folder of its own name in:").arg(win.names(win.job.dialogSources))
        }
        TelamonFolderField {
            id: extractFolder
            Layout.fillWidth: true
            path: win.job.dialogFolder
            title: qsTr("Choose Where to Extract")
            Accessible.name: qsTr("Folder to extract into")
        }
        InfoBanner {
            Layout.fillWidth: true
            type: "error"
            text: win.job.dialogError
            shown: win.job.dialogError !== ""
        }
        Item {
            Layout.fillHeight: true
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: Kirigami.Units.largeSpacing
            SecondaryButton {
                text: qsTr("Cancel")
                onClicked: win.job.closeJob()
            }
            PrimaryButton {
                text: qsTr("Extract")
                enabled: extractFolder.path !== ""
                onClicked: win.job.confirmExtract(extractFolder.path)
            }
        }
    }

    // Compress…
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.gridUnit * 1.5
        spacing: Kirigami.Units.largeSpacing
        visible: win.compressDialog

        TelamonLabel {
            Layout.fillWidth: true
            textStyle: TelamonLabel.Title
            textFormat: Text.PlainText
            text: qsTr("Compress")
        }
        TelamonLabel {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: win.names(win.job.dialogSources)
        }
        TelamonTextField {
            id: archiveName
            Layout.fillWidth: true
            placeholderText: qsTr("Name")
            text: win.job.dialogName
            maximumLength: 200
            Accessible.name: qsTr("Archive name")
        }
        TelamonFolderField {
            id: archiveFolder
            Layout.fillWidth: true
            path: win.job.dialogFolder
            title: qsTr("Choose Where to Save")
            Accessible.name: qsTr("Folder to save in")
        }
        TelamonLabel {
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            text: qsTr("Format")
        }
        TelamonSegmentedControl {
            id: archiveFormat
            Layout.fillWidth: true
            model: [qsTr("ZIP"), qsTr("7z"), qsTr("TAR.GZ"), qsTr("TAR.XZ"), qsTr("TAR.ZST")]
            currentIndex: 0
            Accessible.name: qsTr("Format")
        }
        TelamonLabel {
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            text: qsTr("Level")
        }
        TelamonSegmentedControl {
            id: archiveLevel
            Layout.fillWidth: true
            model: [qsTr("Store"), qsTr("Fast"), qsTr("Normal"), qsTr("Best")]
            currentIndex: 2
            Accessible.name: qsTr("Level")
        }
        InfoBanner {
            Layout.fillWidth: true
            type: "error"
            text: win.job.dialogError
            shown: win.job.dialogError !== ""
        }
        Item {
            Layout.fillHeight: true
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: Kirigami.Units.largeSpacing
            SecondaryButton {
                text: qsTr("Cancel")
                onClicked: win.job.closeJob()
            }
            PrimaryButton {
                text: qsTr("Compress")
                enabled: archiveName.text.trim() !== "" && archiveFolder.path !== ""
                onClicked: win.job.confirmCompress(archiveFolder.path, archiveName.text, win.formats[archiveFormat.currentIndex], win.levels[archiveLevel.currentIndex])
            }
        }
    }

    // The job itself.
    JobView {
        anchors.fill: parent
        visible: !win.extractDialog && !win.compressDialog
        backend: win.job
        canPause: true
        doneText: win.kind === "compress" ? qsTr("Made %1") : win.kind === "test" ? qsTr("No Problems Found") : qsTr("Extracted to %1")
        doneLeftText: win.kind === "compress" ? qsTr("Made %1, but %2 items were left out") : qsTr("Extracted to %1, but %2 items were left out")
        failedText: win.kind === "compress" ? qsTr("Couldn't Compress") : win.kind === "test" ? qsTr("Problems Found") : qsTr("Couldn't Extract")
        leftBanner: win.kind === "compress" ? qsTr("Some items could not be added. The list below says why.") : qsTr("Some items could not be extracted. The list below says why.")
        notDoneHeader: win.kind === "compress" ? qsTr("Not Added") : qsTr("Not Extracted")
    }

    Questions {
        anchors.fill: parent
        backend: win.job
    }
}
