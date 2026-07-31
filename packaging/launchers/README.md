# Trusted launchers

Packet 0 defines rule only. Production launchers arrive in Packet 43. They must invoke fixed interpreter and fixed application path using Python isolated mode; `uv run` is forbidden for trusted production processes.
