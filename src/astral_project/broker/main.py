"""Fixed root broker executable; no caller-selected authority or paths."""

from __future__ import annotations

import sys

from astral_project.broker.config import load_broker_authority, load_broker_install_config
from astral_project.broker.executor import BrokerSessionExecutor
from astral_project.broker.mapping import MappingWorker
from astral_project.broker.registry import ActiveSessionRegistry
from astral_project.broker.server import BrokerPaths, BrokerServer
from astral_project.broker.socket_activation import take_systemd_listener
from astral_project.runtime.installer import load_active_runtime_closure


def main() -> None:
    if sys.argv[1:] not in ([], ["--socket-activation"]):
        raise SystemExit(64)
    config = load_broker_install_config()
    authority = load_broker_authority(config.authority_path)
    manifest = load_active_runtime_closure(config.runtime_root, config.runtime_manifest_digest)
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
        rejection_sink=lambda stage, error: print(
            f"astral broker rejection stage={stage} code={error.code.name} message={error.message}",
            file=sys.stderr,
            flush=True,
        ),
    )
    server.start(inherited_listener=take_systemd_listener())
    try:
        while True:
            server.serve_once()
    finally:
        server.close()


if __name__ == "__main__":
    main()
