"""API package: FastAPI JSON endpoints + static frontend (M6).

TargetGuard is enforced here before any scan starts; the server binds
localhost by default, LAN exposure only via explicit env var.
"""

from netscope.api.app import DEFAULT_ALLOWED_HOSTS, NetScopeAPI, ScanJob, build_app

__all__ = ["DEFAULT_ALLOWED_HOSTS", "NetScopeAPI", "ScanJob", "build_app"]
