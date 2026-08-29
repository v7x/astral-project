# Native workers

Users do not build or install native workers separately. The Ubuntu package
build compiles fixed C workers from `packaging/native/` and installs them under
`/usr/libexec/astral-project/`.

The native boundary is deliberately small and policy-free. Trusted Python
code supplies bounded, typed plans; native workers validate their fixed input,
pin descriptors or mount identities where required, and execute only the
installed transition. Caller-supplied bubblewrap flags, alternate helpers,
alternate entrypoints, and arbitrary native commands are not public features.

For package build and installation, see [package installation](../docs/user/installation.md).
For security assumptions and privilege boundaries, see the [security model](../docs/user/security.md).
