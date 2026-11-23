"""M1 smoke test: the skeleton imports and is wired up.

Real behaviour tests arrive with M2+ (guard, scanner fixtures, store).
"""

import netscope
import netscope.api
import netscope.scanner
import netscope.store


def test_packages_import():
    assert netscope.__version__ == "0.1.0"
    assert netscope.scanner and netscope.api and netscope.store
