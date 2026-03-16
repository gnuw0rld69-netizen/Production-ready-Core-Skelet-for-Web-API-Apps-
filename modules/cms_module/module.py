from .db import CmsBase
from . import models  # noqa: F401
from .routers import admin_router, api_router, public_router, root_handler
from .templates import TEMPLATES_DIR


def get_module():
    return {
        "name": "cms_module",
        "routers": [public_router, admin_router, api_router],
        "templates_dir": TEMPLATES_DIR,
        "metadata": [CmsBase.metadata],
        "admin_entry": {
            "name": "cms_module",
            "label": "CMS",
            "path": "/admin_panel/module_cms_module",
        },
        "root_handler": root_handler,
    }


MODULE = get_module()
