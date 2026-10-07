import QtQuick
import QtQuick.Layouts
import QtQuick.Dialogs
import org.kde.kirigami as Kirigami
import Telamon.Ui

// An archive as folders: Back, Up and the breadcrumb, Extract All…, and the
// folder's rows. Names and reasons come from the archive: always plain text.
Item {
    id: view

    required property var backend

    signal openRequested

    readonly property var crumbList: JSON.parse(view.backend.crumbs || "[]")
    property int total: 0

    function load() {
        const data = JSON.parse(view.backend.folder || "{\"rows\":[],\"total\":0}");
        rows.clear();
        rows.append(data.rows);
        view.total = data.total;
    }

    Component.onCompleted: view.load()
    Connections {
        target: view.backend
        function onFolderChanged() {
            view.load();
        }
    }

    ListModel {
        id: rows
    }

    Shortcut {
        sequences: [StandardKey.Back]
        enabled: view.visible && view.backend.canBack
        onActivated: view.backend.back()
    }
    Shortcut {
        sequences: ["Alt+Up"]
        enabled: view.visible && view.backend.canUp
        onActivated: view.backend.up()
    }

    FolderDialog {
        id: folderDialog
        title: qsTr("Choose Where to Extract")
        function start() {
            // The archive's folder, read now: the dialog is made before any archive is open.
            folderDialog.currentFolder = Qt.url("file://" + view.backend.defaultFolder().split("/").map(encodeURIComponent).join("/"));
            folderDialog.open();
        }
        onAccepted: view.backend.extractAll(selectedFolder.toString())
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Kirigami.Units.largeSpacing
        spacing: Kirigami.Units.largeSpacing

        RowLayout {
            Layout.fillWidth: true
            spacing: Kirigami.Units.smallSpacing

            ToolbarButton {
                symbol: Symbols.ArrowBack
                text: qsTr("Back")
                enabled: view.backend.canBack
                onClicked: view.backend.back()
            }
            ToolbarButton {
                symbol: Symbols.ArrowUpward
                text: qsTr("Up")
                enabled: view.backend.canUp
                onClicked: view.backend.up()
            }
            TelamonBreadcrumb {
                Layout.fillWidth: true
                segments: view.crumbList
                onActivated: index => view.backend.goTo(view.crumbList[index].id)
            }
            SecondaryButton {
                text: qsTr("Open Another…")
                onClicked: view.openRequested()
            }
            PrimaryButton {
                text: qsTr("Extract All…")
                onClicked: folderDialog.start()
            }
        }

        InfoBanner {
            Layout.fillWidth: true
            type: "warning"
            text: qsTr("Part of this archive couldn't be read, so only some of it is shown. %1").arg(view.backend.broken)
            shown: view.backend.broken !== ""
        }

        DataTable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: rows
            selectionMode: DataTable.SingleSelection
            placeholderText: qsTr("This folder is empty")
            Accessible.name: qsTr("Archive contents")
            columns: [
                { title: qsTr("Name"), role: "name", fill: true, iconRole: "icon", sortable: false },
                { title: qsTr("Size"), role: "size", width: 7, align: Qt.AlignRight, sortable: false },
                { title: qsTr("Modified"), role: "mtime", width: 11, sortable: false, text: v => v > 0 ? Qt.formatDateTime(new Date(v), "yyyy-MM-dd HH:mm") : "" }
            ]
            onActivated: row => {
                const r = rows.get(row);
                if (r && r.dir) {
                    view.backend.enter(r.id);
                }
            }
        }

        TelamonLabel {
            Layout.fillWidth: true
            visible: view.total > rows.count
            textStyle: TelamonLabel.Caption
            textFormat: Text.PlainText
            text: qsTr("Showing the first %1 of %2 items in this folder.").arg(rows.count).arg(view.total)
        }
    }
}
