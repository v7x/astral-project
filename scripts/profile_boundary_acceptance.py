#!/usr/bin/env python3
"""Packaged profile, environment, and resource boundary acceptance driver."""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import threading
import time
from contextlib import suppress
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from astral_project import cli
from astral_project.homed.host import HostAccessError, HostReadonlyView
from astral_project.homed.mediation import MediationDecision, UnknownPathMediator
from astral_project.learner import ProfileLearner
from astral_project.profile import (
    CredentialRule,
    Profile,
    Rule,
    RuleMode,
    RuleScope,
    Sensitivity,
    SocketRule,
    WarningLevel,
)
from astral_project.profile_lifecycle import ProfileStore
from astral_project.sandbox.environment import EnvironmentPolicy
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode
from astral_project.sandbox.resources import ResourcePolicy
from astral_project.sandbox.runner import run_plan


def _run(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(arguments, env=environment, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{arguments!r} failed: {result.returncode}: {result.stderr}")
    return result.stdout


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p33-36-") as temp:
        base = Path(temp)
        home = base / "home"
        home.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(base / "home"),
                "XDG_CONFIG_HOME": str(base / "config"),
                "XDG_STATE_HOME": str(base / "state"),
                "XDG_RUNTIME_DIR": str(base / "runtime"),
            }
        )
        _run(["aspr", "profile", "create", "agents-default", "--name", "Agents"], environment)
        review = _run(["aspr", "profile", "review", "agents-default"], environment)
        if 'id = "agents-default"' not in review:
            raise AssertionError("created profile was not reviewable")
        _run(["aspr", "profile", "seal", "agents-default"], environment)
        sealed = _run(["aspr", "profile", "review", "agents-default"], environment)
        if "sealed = true" not in sealed:
            raise AssertionError("profile did not seal")
        _run(["aspr", "profile", "unseal", "agents-default"], environment)
        store = ProfileStore(base / "config" / "astral-project")
        profile = store.load("agents-default")
        forwarded: list[str] = []

        def capture_runner(arguments: list[str], **_kwargs: object) -> int:
            forwarded.extend(arguments)
            return 0

        ProfileLearner(
            store,
            state_root=base / "state",
            home_root=home,
            sandbox_runner=capture_runner,
        ).run(
            "agents-default",
            ("/bin/true",),
            runtime=base / "runtime",
            grant_id="grant-id",
            remotes=(
                "grant-id:/source=/remote:ro",
                "grant-id:/second=/remote-two:ro",
            ),
            daemon_request=lambda _operation, _payload=None: {},
        )
        expected_remote_options = [
            "--grant",
            "grant-id",
            "--remote",
            "grant-id:/source=/remote:ro",
            "--remote",
            "grant-id:/second=/remote-two:ro",
        ]
        if (
            forwarded[forwarded.index("--grant") : forwarded.index("--profile")]
            != expected_remote_options
        ):
            raise AssertionError("learner remote binding was not forwarded")

        cli_forwarded: list[dict[str, object]] = []

        class CaptureLearner:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def run(self, *_args: object, **kwargs: object) -> int:
                cli_forwarded.append(kwargs)
                return 0

        with (
            patch.dict(os.environ, environment),
            patch.object(cli, "ProfileLearner", CaptureLearner),
        ):
            cli_result = cli.run(
                [
                    "profile",
                    "learn",
                    "agents-default",
                    "--grant",
                    "grant-id",
                    "--remote",
                    "grant-id:/source=/remote:ro",
                    "--remote",
                    "grant-id:/second=/remote-two:ro",
                    "--",
                    "/bin/true",
                ],
                stdout=StringIO(),
                stderr=StringIO(),
            )
        if cli_result != 0 or not cli_forwarded:
            raise AssertionError("profile learn CLI did not run")
        if cli_forwarded[-1].get("remotes") != [
            "grant-id:/source=/remote:ro",
            "grant-id:/second=/remote-two:ro",
        ]:
            raise AssertionError("profile learn CLI dropped repeated remote bindings")
        socket_path = base / "safe.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        try:
            secured = Profile(
                profile.version,
                profile.profile_id,
                profile.name,
                rules=(
                    Rule(
                        ".config/token",
                        RuleScope.EXACT,
                        RuleMode.HOST_RO,
                        Sensitivity.CREDENTIAL,
                    ),
                ),
                sockets=(
                    SocketRule(str(socket_path), Sensitivity.CREDENTIAL, WarningLevel.STRONG),
                ),
                credentials=(CredentialRule(".config/token"),),
                environment_allow=("LANG", "PATH"),
                environment_unset=("TERM",),
            )
            store.save(secured, expected_revision=profile.revision)
            policy = ResourcePolicy(store.load("agents-default"))
            if (
                policy.socket(socket_path).allowed
                or not policy.socket(socket_path, strong_confirmation=True).allowed
            ):
                raise AssertionError("credential-sensitive socket confirmation policy is invalid")
            if policy.credential(".config/token").allowed:
                raise AssertionError("credential bypassed strong confirmation")
            credential_path = home / ".config" / "token"
            credential_path.parent.mkdir(parents=True)
            credential_path.write_text("secret", encoding="utf-8")
            with HostReadonlyView(home, store.load("agents-default")) as view:
                try:
                    view.read(".config/token")
                except HostAccessError:
                    pass
                else:
                    raise AssertionError("credential host rule bypassed confirmation")
            credential_mediator = UnknownPathMediator(timeout=1)
            credential_view = HostReadonlyView(
                home,
                store.load("agents-default"),
                mediator=credential_mediator,
                session_id="credential-acceptance",
            )
            for request_number in (1, 2):
                credential_result: list[bytes] = []
                credential_thread = threading.Thread(
                    target=lambda result=credential_result: result.append(
                        credential_view.read(".config/token")
                    )
                )
                credential_thread.start()
                deadline = time.monotonic() + 5
                while not credential_mediator.pending() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not credential_mediator.pending():
                    raise AssertionError("credential confirmation was not requested")
                credential_mediator.decide(
                    session_id="credential-acceptance",
                    request_number=request_number,
                    decision=MediationDecision.ALLOW_ONCE,
                )
                credential_thread.join(timeout=5)
                if credential_result != [b"secret"]:
                    raise AssertionError("strong credential confirmation did not authorize access")
            credential_view.close()
            raw_policy = ResourcePolicy(Profile(1, "raw", "raw", raw_socket=True))
            if (
                raw_policy.raw_socket().allowed
                or not raw_policy.raw_socket(strong_confirmation=True).allowed
            ):
                raise AssertionError("raw socket confirmation policy is invalid")
            filtered = EnvironmentPolicy(
                allowed_names=frozenset({"LANG", "PATH", "AWS_SECRET_ACCESS_KEY"})
            ).sanitize(
                {"LANG": "C", "PATH": str(base), "AWS_SECRET_ACCESS_KEY": "redacted"},
                visible_paths=(base,),
            )
            if "AWS_SECRET_ACCESS_KEY" in filtered.values:
                raise AssertionError("secret-like environment value survived")

            public_socket_path = Path("/tmp/aspr-p36-public.sock")
            if public_socket_path.exists() or public_socket_path.is_symlink():
                raise AssertionError("temporary public socket path is already occupied")
            public_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            public_listener.bind(str(public_socket_path))
            public_socket_path.chmod(0o666)
            public_listener.listen(1)
            try:
                socket_profile = Profile(
                    1,
                    "agents-default",
                    "Agents",
                    sockets=(SocketRule(str(public_socket_path), Sensitivity.OTHER),),
                )
                store.save(socket_profile, expected_revision=store.load("agents-default").revision)
                socket_process = subprocess.Popen(
                    [
                        "aspr",
                        "sandbox",
                        "--network",
                        "none",
                        "--profile",
                        str(store.path("agents-default")),
                        "--home-root",
                        str(home),
                        "--",
                        "/usr/bin/python3",
                        "-c",
                        (
                            "import socket; s=socket.socket(socket.AF_UNIX); "
                            f"s.connect({str(public_socket_path)!r}); s.sendall(b'ping'); "
                            "print(s.recv(4).decode())"
                        ),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                public_listener.settimeout(10)
                try:
                    connection, _ = public_listener.accept()
                except TimeoutError as error:
                    socket_stdout, socket_stderr = socket_process.communicate(timeout=20)
                    raise AssertionError(
                        "installed socket client did not connect: "
                        f"{socket_process.returncode}: {socket_stdout} {socket_stderr}"
                    ) from error
                with connection:
                    if connection.recv(4) != b"ping":
                        raise AssertionError("sandbox socket client sent the wrong payload")
                    connection.sendall(b"pong")
                socket_stdout, socket_stderr = socket_process.communicate(timeout=20)
                if socket_process.returncode != 0:
                    raise AssertionError(
                        "installed socket access failed: "
                        f"{socket_process.returncode}: {socket_stdout} {socket_stderr}"
                    )
                print("installed-exact-socket-access=passed")
            finally:
                public_listener.close()
                with suppress(FileNotFoundError):
                    public_socket_path.unlink()
        finally:
            listener.close()
        raw_profile_path = base / "raw-profile.toml"
        raw_profile_path.write_text(
            Profile(1, "raw", "raw", raw_socket=True).to_toml(), encoding="utf-8"
        )
        raw_result = subprocess.run(
            [
                "aspr",
                "sandbox",
                "--network",
                "inherit",
                "--profile",
                str(raw_profile_path),
                "--home-root",
                str(home),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if raw_result.returncode == 0 or "raw socket" not in raw_result.stderr:
            raise AssertionError("public sandbox did not deny raw socket opt-in")
        path_environment = environment.copy()
        path_environment["PATH"] = "/usr/bin:/not-visible"
        with patch.dict(os.environ, path_environment):
            path_result = run_plan(
                LocalSandboxPlan(
                    ("/bin/sh", "-c", 'test "$PATH" = /usr/bin'),
                    NetworkMode.NONE,
                ),
                environment_policy=EnvironmentPolicy(allowed_names=frozenset({"PATH"})),
            )
        if path_result != 0:
            raise AssertionError(f"native PATH propagation failed: {path_result}")
        exported = base / "export.toml"
        store.export("agents-default", exported)
        imported_store = ProfileStore(base / "imported-config" / "astral-project")
        imported_store.import_profile(exported)
        if (
            imported_store.load("agents-default").to_toml()
            != store.load("agents-default").to_toml()
        ):
            raise AssertionError("profile export/import changed semantics")
        print("profile-lifecycle-compatibility=passed")
        print("environment-secret-and-path-boundary=passed")
        print("socket-credential-boundary=passed")
        print("credential-projected-home-confirmation=passed")
        print("raw-socket-denial=passed")
        print("native-path-propagation=passed")
        print("learner-remote-forwarding=passed")
        print("profile-export-import-semantics=passed")
        print("packaged-profile-boundary-acceptance=passed")


if __name__ == "__main__":
    main()
