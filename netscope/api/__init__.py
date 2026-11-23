"""API package: FastAPI JSON endpoints + static frontend (M6).

TargetGuard is enforced here before any scan starts; the server binds
localhost by default, LAN exposure only via explicit env var.
"""

from netscope.api.app import NetScopeAPI, ScanJob, build_app

__all__ = ["NetScopeAPI", "ScanJob", "build_app"]
