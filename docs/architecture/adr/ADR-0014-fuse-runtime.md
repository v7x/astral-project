# ADR-0014: Projected-home FUSE runtime

- **Status:** Accepted
- **Scope:** Packets 25–36

## Decision

`aspr-homed` uses Ubuntu's `python3-pyfuse3` dependency and its declared Python
runtime closure (including `trio`). The Astral package remains pure Python and
explicitly depends on `python3-pyfuse3`, `python3-cbor2`, and
`python3-cryptography`; it never relies on host-built extension wheels or
`/usr/local` imports. Certification is per release and exact package version, recorded
in the Ubuntu 24.04 and 26.04 raw acceptance transcripts. The trusted daemon starts
only through the fixed installed `aspr-homed` entrypoint under isolated Python; it
does not import from the parent interpreter, `PYTHONPATH`, user site, or a dynamically
assembled command.

## Security effect

The FUSE binding and async runtime are part of the trusted runtime closure. Missing
runtime fails startup loudly. A new Ubuntu binding version is not silently equivalent:
it requires an installed acceptance run and an exact transcript entry before it is
certified. Development imports and ambient `/usr/local` packages are not production
certification evidence.
