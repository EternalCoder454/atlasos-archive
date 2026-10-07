import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Telamon.Ui

// The job window: "Extracting photos.zip", progress and Cancel; when done
// "Extracted to Photos" with Show Files and Close, and what was skipped.
Item {
    id: view

    required property var backend

    readonly property string state: view.backend.jobState
    readonly property var details: JSON.parse(view.backend.jobDetails || "{\"rows\":[],\"more\":0}")
    readonly property string resultName: {
        const parts = view.backend.jobResultShown.split("/").filter(p => p !== "");
        return parts.length > 0 ? parts[parts.length - 1] : view.backend.jobResultShown;
    }

    function close() {
        if (view.backend.jobOnly) {
            Qt.quit();
        } else {
            view.backend.closeJob();
        }
    }

    ListModel {
        id: skipped
    }
    onDetailsChanged: {
        skipped.clear();
        skipped.append(view.details.rows);
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.gridUnit * 2
        spacing: Kirigami.Units.largeSpacing

        Item {
            Layout.fillHeight: !list.visible
            Layout.preferredHeight: 0
        }

        TelamonLabel {
            Layout.fillWidth: true
            textStyle: TelamonLabel.Title
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            text: view.state === "done" ? (view.backend.jobLeft > 0 ? qsTr("Extracted to %1, but %2 items were left out").arg(view.resultName).arg(view.backend.jobLeft) : qsTr("Extracted to %1").arg(view.resultName)) : view.state === "failed" ? qsTr("Couldn't Extract") : view.backend.jobTitle
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: view.state === "done"
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignHCenter
            elide: Text.ElideMiddle
            text: view.backend.jobResultShown
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: text !== ""
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignHCenter
            text: view.backend.jobQueue
        }

        TelamonProgressBar {
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: Kirigami.Units.gridUnit * 28
            visible: view.state === "running"
            value: Math.max(0, view.backend.jobFraction)
            indeterminate: view.backend.jobFraction < 0
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: view.state === "running" && text !== ""
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignHCenter
            text: view.backend.jobText
        }

        InfoBanner {
            Layout.fillWidth: true
            type: "error"
            text: view.backend.jobError
            shown: view.backend.jobError !== "" && (view.state === "failed" || view.state === "done")
        }

        InfoBanner {
            Layout.fillWidth: true
            type: "warning"
            text: qsTr("Some items could not be extracted. The list below says why.")
            shown: view.state === "done" && view.backend.jobLeft > 0
        }

        InfoBanner {
            Layout.fillWidth: true
            type: "warning"
            text: view.backend.jobWarning
            shown: view.backend.jobWarning !== ""
        }

        DataTable {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: view.state === "done" && (skipped.count > 0 || view.details.more > 0)
            model: skipped
            selectionMode: DataTable.SingleSelection
            Accessible.name: qsTr("Items that were not extracted")
            columns: [
                { title: qsTr("Not Extracted"), role: "name", fill: true, sortable: false },
                { title: qsTr("Why"), role: "reason", width: 22, sortable: false }
            ]
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: list.visible && list.currentIndex >= 0 && list.currentIndex < skipped.count
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: list.currentIndex >= 0 && list.currentIndex < skipped.count ? skipped.get(list.currentIndex).reason : ""
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: list.visible && view.details.more > 0
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            text: qsTr("And %1 more.").arg(view.details.more)
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: Kirigami.Units.largeSpacing

            SecondaryButton {
                visible: view.state === "running"
                text: qsTr("Cancel")
                onClicked: view.backend.cancelJob()
            }
            SecondaryButton {
                visible: view.state === "done" || view.state === "failed" || view.state === "cancelled"
                text: qsTr("Close")
                onClicked: view.close()
            }
            PrimaryButton {
                visible: view.state === "done" && view.backend.jobResult !== ""
                text: qsTr("Show Files")
                onClicked: view.backend.showFiles()
            }
        }

        Item {
            Layout.fillHeight: !list.visible
            Layout.preferredHeight: 0
        }
    }
}
