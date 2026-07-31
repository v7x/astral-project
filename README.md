# Astral Project

Note: Astral Project is currently a work in progress, and has largely been autonomously written based on an extensive architecture. This is will likely need a deslopification pass, so use at your own risk until then!

Astral Project gives coding agents least-authority remote-file access. Version 1 targets Linux and Python 3.12.

## Commands

```bash
astral-project version
aspr version --json
```

Both names execute same CLI entry point. `version --json` emits stable machine-readable version data.

## Development

```bash
uv sync --locked --all-groups
./scripts/test
```

`uv.lock` is mandatory. Update dependency declarations and lockfile in same reviewed change.

## Trusted-process launch rule

Production daemon, remote helper, transport, and FUSE processes must use fixed interpreter and fixed application path with Python isolated mode:

```text
/fixed/python -I /fixed/astral-project/application-entrypoint ...
```

Launchers must remove `PYTHON*` variables. They must not import current directory, project directory, user site-packages, `.pth` code, harness plugins, or user-controlled `PYTHONPATH`. `uv run` is development-only; never production trusted-process launcher.

No production runtime dependency exists in Packet 0. Later runtime dependencies require locked, verified artifacts before trusted use.
