"""Worker log and termination supervision tests."""

from __future__ import annotations

import os

from astral_project.broker.mapping import WorkerProcess
from astral_project.broker.supervision import WorkerLogPipe, supervise_worker


def test_supervision_captures_worker_stderr_outside_stream() -> None:
    logs = WorkerLogPipe.create()
    child = os.fork()
    if child == 0:
        try:
            os.close(logs.read_descriptor)
            os.write(logs.write_descriptor, b"native worker diagnostic\n")
            os._exit(7)
        except OSError:
            os._exit(111)
    os.close(logs.write_descriptor)
    logs.write_descriptor = -1

    result = supervise_worker(WorkerProcess(child), logs, timeout_seconds=1)

    assert result.exit_code == 7
    assert result.signal is None
    assert result.stderr == b"native worker diagnostic\n"
    assert result.stderr_truncated is False
