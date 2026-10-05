import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import Atlas.Ui

// Atlas Archive's window. With no archive open it is the centred hero; the F
// phase adds the archive view, the dialogs and the job windows
// (docs/DESIGN.md, "Look").
AtlasWindow {
    id: root

    // The Rust backend (src/backend.rs); main.cpp sets it.
    required property var backend

    title: AtlasApp.name
    width: Kirigami.Units.gridUnit * 52
    height: Kirigami.Units.gridUnit * 34
    minimumWidth: Kirigami.Units.gridUnit * 24
    minimumHeight: Kirigami.Units.gridUnit * 18
    stateKey: "main"
    visible: true
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - Kirigami.Units.gridUnit * 4, Kirigami.Units.gridUnit * 28)
        spacing: Kirigami.Units.largeSpacing * 2

        StatusHero {
            Layout.alignment: Qt.AlignHCenter
            iconName: "package-x-generic"
            headline: qsTr("No Archive Open")
            subtitle: qsTr("Open an archive to see what's inside, or drop files here to compress them.")
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: Kirigami.Units.largeSpacing

            PrimaryButton {
                text: qsTr("Open Archive…")
                enabled: false
            }
            SecondaryButton {
                text: qsTr("Create Archive…")
                enabled: false
            }
        }
    }
}
