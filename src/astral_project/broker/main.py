"""Fixed root broker executable; no caller-selected authority or paths."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from astral_project.broker.config import load_broker_authority, load_broker_install_config
from astral_project.broker.executor import BrokerSessionExecutor
from astral_project.broker.mapping import MappingWorker
from astral_project.broker.registry import ActiveSessionRegistry
from astral_project.broker.server import BrokerPaths, BrokerServer
from astral_project.runtime.closure import discover_sftp_runtime


def main() -> None:
    if sys.argv[1:] not in ([], ["--socket-activation"]):
        raise SystemExit(64)
    config = load_broker_install_config()
    authority = load_broker_authority(config.authority_path)
    with tempfile.TemporaryDirectory(prefix="aspr-runtime-manifest-") as temporary:
        manifest = discover_sftp_runtime(
            Path("/usr/lib/openssh/sftp-server"), generated_directory=Path(temporary)
        )
    if manifest.digest() != config.runtime_manifest_digest:
        raise SystemExit(70)
    registry = ActiveSessionRegistry()
    server = BrokerServer(
        BrokerPaths(config.socket_path),
        authority,
        executor=BrokerSessionExecutor(
            ceiling=authority.server_ceiling,
            runtime_root=config.runtime_root,
            runtime_manifest=manifest,
            mapping_worker=MappingWorker(config.mount_worker),
        ),
        active_session_sink=registry.register_from_server,
    )
    server.start()
    try:
        while True:
            server.serve_once()
    finally:
        server.close()


if __name__ == "__main__":
    main()
