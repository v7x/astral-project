# Contributing

Use Python 3.12 through `uv` for development and type checking. Keep `uv.lock` with every dependency change. Run checked-in local gates (`uv lock --check`, locked sync, `./scripts/test`, and `git diff --check`) before submission. Hosted GitHub Actions execution is intentionally deferred while core packet sequence is under development because account billing is unavailable; installed package gates remain authoritative. Ubuntu package gates certify distro interpreters tested on the VMs: Python 3.12.3 on Ubuntu 24.04 and Python 3.14.4 on Ubuntu 26.04; do not infer support for untested interpreters.

Before review:

```bash
./scripts/test
./scripts/check-lock
```

Do not weaken security boundary, use `shell=True`, add user-plugin loading to trusted process, or add unreviewed native syscall code. Follow packet order in caveman implementation plan.
