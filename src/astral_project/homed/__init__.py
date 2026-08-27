"""Projected-home backends and FUSE lifecycle helpers."""

from astral_project.homed.overlay import OverlayBackend, OverlayFeatures, OverlayStateError
from astral_project.homed.private import PrivateStateError, PrivateWritableBackend

__all__ = [
    "OverlayBackend",
    "OverlayFeatures",
    "OverlayStateError",
    "PrivateStateError",
    "PrivateWritableBackend",
]
