from .auth import router as auth_router
from .users import router as users_router
from .web_admin import router as web_admin_router
from .web_users import router as web_users_router

__all__ = ["auth_router", "users_router", "web_users_router", "web_admin_router"]
