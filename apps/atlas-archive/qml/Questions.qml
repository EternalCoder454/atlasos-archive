import QtQuick
import QtQuick.Layouts
import QtQuick.Templates as T
import org.kde.kirigami as Kirigami
import Atlas.Ui

// What a job asks, in plain words: a password, a safety limit, a name that is
// already there. Each answer goes back to the parked job; a password is
// cleared from the field as soon as it is sent.
Item {
    id: questions

    required property var backend

    AtlasDialog {
        id: password
        title: qsTr("Password Needed")
        showClose: false
        closePolicy: T.Popup.CloseOnEscape
        visible: questions.backend.question === "password"
        onClosed: {
            field.text = "";
            if (questions.backend.question === "password") {
                questions.backend.cancelPassword();
            }
        }
        function submit() {
            if (field.text.length === 0) {
                return;
            }
            questions.backend.answerPassword(field.text);
            field.text = "";
        }
        footerContent: [
            SecondaryButton {
                text: qsTr("Cancel")
                onClicked: password.close()
            },
            PrimaryButton {
                text: qsTr("Open")
                enabled: field.text.length > 0
                onClicked: password.submit()
            }
        ]
        AtlasLabel {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: questions.backend.questionText
        }
        AtlasPasswordField {
            id: field
            Layout.fillWidth: true
            placeholderText: qsTr("Password")
            maximumLength: 4096
            errorText: questions.backend.passwordNote !== "" ? questions.backend.passwordNote : questions.backend.questionWrong ? qsTr("That password didn't work") : ""
            onAccepted: password.submit()
        }
    }

    AtlasDialog {
        id: limit
        title: qsTr("Safety Limit Reached")
        showClose: false
        closePolicy: T.Popup.NoAutoClose
        visible: questions.backend.question === "limit"
        footerContent: [
            SecondaryButton {
                text: qsTr("Stop")
                onClicked: questions.backend.answerLimit(false)
            },
            PrimaryButton {
                text: qsTr("Unpack Anyway")
                onClicked: questions.backend.answerLimit(true)
            }
        ]
        AtlasLabel {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: questions.backend.questionText
        }
    }

    AtlasDialog {
        id: clash
        title: qsTr("Already Here")
        showClose: false
        closePolicy: T.Popup.NoAutoClose
        visible: questions.backend.question === "clash"
        onClosed: all.checked = false
        footerContent: [
            SecondaryButton {
                text: qsTr("Replace")
                onClicked: questions.backend.answerClash(0, all.checked)
            },
            SecondaryButton {
                text: qsTr("Skip")
                onClicked: questions.backend.answerClash(1, all.checked)
            },
            PrimaryButton {
                text: qsTr("Keep Both")
                onClicked: questions.backend.answerClash(2, all.checked)
            }
        ]
        AtlasLabel {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: qsTr("\"%1\" is already here. Do you want to replace it, skip it, or keep both?").arg(questions.backend.questionText)
        }
        AtlasCheckBox {
            id: all
            text: qsTr("Do this for all conflicts")
        }
    }
}
