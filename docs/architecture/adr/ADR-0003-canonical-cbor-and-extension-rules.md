# ADR-0003: Canonical CBOR and extension rules

## Problem

Grant signatures need deterministic bytes across local daemon and remote helper.

## Choices

- `cbor2` canonical encoding plus Ed25519 over unsigned grant payload.
- JSON signing, noncanonical CBOR, or custom binary encoder.

## Chosen choice

Version-1 grant payload is canonical CBOR. Envelope stores canonical payload and 64-byte Ed25519 signature. Signature covers every payload field. Payload has separate mandatory and optional extension maps. Unknown mandatory extension rejects. Unknown optional extension is retained and only accepted when verifier policy permits it.

Times are integer UTC seconds. Nonce is exactly 32 bytes. IDs are ADR-0002 UUID4 strings.

## Security effect

Canonical re-encoding check rejects ambiguous CBOR. Context verification binds host ID, SSH host-key fingerprint, remote user, and time window. Extension rules prevent silent authorization changes. Mutable temporary private-key buffers are zeroized; cryptography backend key objects and immutable Python `bytes` cannot promise memory zeroization.

## Rejected choices

- JSON: encoding edge cases and weaker binary protocol fit.
- Noncanonical CBOR: same structure can sign different bytes.
- Unknown mandatory extensions accepted: future critical restriction could be ignored.

## Tests

- deterministic canonical bytes and signature;
- each bound field mutation invalidates signature;
- context and time rejection;
- extension-policy tests;
- checked-in deterministic binary fixture.

## Reconsideration trigger

Protocol version 2 needs a field incompatible with this schema or a reviewed CBOR implementation defect appears.
