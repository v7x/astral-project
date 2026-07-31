# Contributing

Use Python 3.12 through `uv`. Keep `uv.lock` with every dependency change.

Before review:

```bash
./scripts/test
./scripts/check-lock
```

Do not weaken security boundary, use `shell=True`, add user-plugin loading to trusted process, or add unreviewed native syscall code. Follow packet order in caveman implementation plan.
