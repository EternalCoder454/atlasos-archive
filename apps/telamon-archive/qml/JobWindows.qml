pragma ComponentBehavior: Bound

import QtQuick

// One window for each job that has something to show: the progress of a job
// started with `show_progress` (the default), a question (a password, a name
// that is taken, a safety limit), and the Extract All and Compress dialogs.
// The jobs are `JobItem`s from cpp/service.cpp.
QtObject {
    id: root

    required property var service

    readonly property Instantiator windows: Instantiator {
        // A window is made when its row is added (its `job` role fills the
        // window's `job`) and goes when the row does.
        model: root.service.windowModel
        delegate: JobWindow {
            service: root.service
        }
    }
}
