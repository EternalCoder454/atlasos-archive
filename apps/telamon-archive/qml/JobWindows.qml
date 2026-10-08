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
        model: root.service.windows
        delegate: JobWindow {
            required property var modelData
            job: modelData
            service: root.service
        }
    }
}
