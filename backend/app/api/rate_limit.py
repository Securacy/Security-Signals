"""Rate limiting configuration for brute-force protection.

Phase 6: Applied per-route (currently just login) rather than as a global
default, so it doesn't affect unrelated endpoints (e.g. the public signals
API) unless explicitly opted in.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[])
