"""Real descriptor-3 socket activation adoption, without systemd or root install."""

from __future__ import annotations

import os
import socket

from astral_project.broker.socket_activation import take_systemd_listener


def test_take_systemd_listener_adopts_real_fd_three() -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind("\x00aspr-systemd-fd3-test")
    listener.listen(1)
    try:
        saved = os.dup(3)
    except OSError:
        saved = None
    try:
        os.dup2(listener.fileno(), 3)
        adopted = take_systemd_listener({"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"})
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect("\x00aspr-systemd-fd3-test")
            accepted, _ = adopted.accept()
            accepted.close()
            client.close()
        finally:
            adopted.close()
    finally:
        if saved is None:
            os.close(3)
        else:
            os.dup2(saved, 3)
            os.close(saved)
        listener.close()
