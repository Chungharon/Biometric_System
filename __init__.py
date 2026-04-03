"""
biometric_system package init.

Exposes the top-level public API so other scripts can do:
    from biometric_system import config, database, enrollment, authentication
"""

from . import config          # noqa: F401
from . import database        # noqa: F401
from . import utils           # noqa: F401
from . import enrollment      # noqa: F401
from . import authentication  # noqa: F401
from . import access_log      # noqa: F401
from . import admin           # noqa: F401
