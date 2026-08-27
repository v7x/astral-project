# ADR-0014: Projected-home FUSE runtime

- **Status:** Accepted
- **Scope:** Packets 25–36

## Decision

`aspr-homed` uses `pyfuse3==3.5.0` and `trio==0.31.0`, installed in the Astral
package's private Python bundle. The trusted daemon starts only through the fixed
installed `aspr-homed` entrypoint under isolated Python; it does not import from the
parent interpreter, `PYTHONPATH`, user site, or a dynamically assembled command.

## Security effect

The FUSE binding and async runtime are part of the trusted runtime closure. Missing
or mismatched runtime fails startup loudly. Development imports and distro packages
are not production certification evidence.
