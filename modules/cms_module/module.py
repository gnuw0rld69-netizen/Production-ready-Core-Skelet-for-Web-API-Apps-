from __future__ import annotations

import enum
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from app.core.database import get_db
from app.core.dependencies import get_client_ip
from app.core.security import InvalidTokenError, decode_token
from app.models.user import User, UserRole
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService
from app.web.i18n import get_translations, normalize_lang
from app.web.session import get_current_user_from_cookie


REPO_ROOT = Path(__file__).resolve().parents[2]
APP_TEMPLATES_DIR = REPO_ROOT / "app" / "templates"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TRANSLATIONS_DIR = Path(__file__).resolve().parent / "i18n"

_MODULE_TRANSLATIONS: dict[str, dict[str, str]] = {}

env = Environment(
    loader=ChoiceLoader(
        [
            FileSystemLoader(str(TEMPLATES_DIR)),
            FileSystemLoader(str(APP_TEMPLATES_DIR)),
        ]
    ),
    autoescape=True,
)
templates = Jinja2Templates(env=env)


class CmsAccessLevel(str, enum.Enum):
    PUBLIC = "public"
    AUTH = "auth"
    ROLE = "role"


class CmsBase(DeclarativeBase):
    pass


class CmsPage(CmsBase):
    __tablename__ = "cms_module_pages"
    __table_args__ = (UniqueConstraint("lang", "slug", name="uq_cms_module_pages_lang_slug"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    lang: Mapped[str] = mapped_column(String(5), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content_html: Mapped[str] = mapped_column(Text, nullable=False)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    access_level: Mapped[CmsAccessLevel] = mapped_column(SqlEnum(CmsAccessLevel), default=CmsAccessLevel.PUBLIC)
    allowed_roles: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), onupdate=func.now())


class CmsPageCreate(BaseModel):
    slug: str = Field(..., min_length=1)
    lang: str = Field(..., min_length=2, max_length=5)
    title: str = Field(..., min_length=1)
    content_html: str = Field(..., min_length=1)
    is_published: bool = False
    is_root: bool = False
    access_level: CmsAccessLevel = CmsAccessLevel.PUBLIC
    allowed_roles: list[str] = Field(default_factory=list)


class CmsPageUpdate(CmsPageCreate):
    pass


ADMIN_ROLES = {UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPERUSER}


def _msg(lang: str, key: str, fallback: str) -> str:
    t = get_translations(lang).copy()
    t.update(_get_module_translations(lang))
    return t.get(key, fallback)


def _get_module_translations(lang: str) -> dict[str, str]:
    if lang in _MODULE_TRANSLATIONS:
        return _MODULE_TRANSLATIONS[lang]
    path = TRANSLATIONS_DIR / f"{lang}.json"
    if not path.exists():
        _MODULE_TRANSLATIONS[lang] = {}
        return _MODULE_TRANSLATIONS[lang]
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        _MODULE_TRANSLATIONS[lang] = {}
        return _MODULE_TRANSLATIONS[lang]
    _MODULE_TRANSLATIONS[lang] = {str(k): str(v) for k, v in data.items()}
    return _MODULE_TRANSLATIONS[lang]


def _redirect_with_message(lang: str, path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"/{lang}{path}?message={message}", status_code=status.HTTP_303_SEE_OTHER)


def _parse_roles(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _serialize_roles(roles: list[str]) -> str:
    return ",".join(sorted({role.strip() for role in roles if role.strip()}))


def _allowed_role_values() -> set[str]:
    return {role.value for role in ADMIN_ROLES}


def _require_admin_user(request: Request, db: Session) -> User | None:
    user = get_current_user_from_cookie(request, db, require_verified=True)
    if not user:
        return None
    if user.role not in ADMIN_ROLES:
        return None
    return user


def _get_page_by_slug(db: Session, lang: str, slug: str) -> CmsPage | None:
    return db.query(CmsPage).filter(CmsPage.lang == lang, CmsPage.slug == slug).first()


def _get_published_page(db: Session, lang: str, slug: str) -> CmsPage | None:
    return (
        db.query(CmsPage)
        .filter(CmsPage.lang == lang, CmsPage.slug == slug, CmsPage.is_published.is_(True))
        .first()
    )


def _get_root_page(db: Session, lang: str) -> CmsPage | None:
    return (
        db.query(CmsPage)
        .filter(CmsPage.lang == lang, CmsPage.is_root.is_(True), CmsPage.is_published.is_(True))
        .first()
    )


def _unset_root_for_lang(db: Session, lang: str, current_id: int | None = None) -> None:
    query = db.query(CmsPage).filter(CmsPage.lang == lang, CmsPage.is_root.is_(True))
    if current_id is not None:
        query = query.filter(CmsPage.id != current_id)
    query.update({CmsPage.is_root: False})


def _page_allows_user(page: CmsPage, user: User | None) -> bool:
    if page.access_level == CmsAccessLevel.PUBLIC:
        return True
    if page.access_level == CmsAccessLevel.AUTH:
        return bool(user and user.is_verified)
    roles = set(_parse_roles(page.allowed_roles))
    if not roles:
        return False
    return bool(user and user.role.value in roles)


def _get_api_user_optional(request: Request, db: Session) -> User | None:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = decode_token(token)
    except InvalidTokenError:
        return None
    if payload.get("type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    try:
        user_id_int = int(str(user_id))
    except (TypeError, ValueError):
        return None
    user = UserService.get_by_id(db, user_id_int)
    if not user or not user.is_active or not user.is_verified:
        return None
    client_ip = get_client_ip(request)
    if not UserIpAllowlistService.is_ip_allowed(db, user.id, client_ip):
        return None
    return user


def _preferred_lang(request: Request) -> str:
    header = request.headers.get("accept-language", "").lower()
    if "ru" in header:
        return "ru"
    if "en" in header:
        return "en"
    return "ru"


def _render_page_response(request: Request, db: Session, lang: str, page: CmsPage) -> Response:
    user = get_current_user_from_cookie(request, db, require_verified=False)
    if user and not user.is_verified:
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
        )
    if not _page_allows_user(page, user):
        if not user:
            return _redirect_with_message(
                lang,
                "/users/auth",
                _msg(lang, "web.msg.login_required", "Please login first"),
            )
        if not user.is_verified:
            return _redirect_with_message(
                lang,
                "/users/profile",
                _msg(lang, "web.msg.email_not_verified", "Email is not verified"),
            )
        return _redirect_with_message(
            lang,
            "/users/profile",
            _msg(lang, "web.msg.unauthorized", "Unauthorized"),
        )

    t = get_translations(lang).copy()
    t.update(_get_module_translations(lang))
    message = request.query_params.get("message")
    return templates.TemplateResponse(
        "pages/detail.html",
        {
            "request": request,
            "message": message,
            "lang": lang,
            "t": t,
            "page": page,
            "nav_user": user,
            "user": user,
        },
    )


cms_router = APIRouter(tags=["CMS Module"])
admin_router = APIRouter(prefix="/{lang}/admin_panel/module_cms_module", tags=["CMS Module Admin"])
api_router = APIRouter(prefix="/api/v1/cms", tags=["CMS Module API"])


@cms_router.get("/{lang}/pages/{slug}", response_class=HTMLResponse)
def cms_page(request: Request, lang: str, slug: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        page = _get_published_page(db, lang, slug)
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        return _render_page_response(request, db, lang, page)
    finally:
        db.close()


@admin_router.get("/", response_class=HTMLResponse)
def cms_admin_list(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang).copy()
        t.update(_get_module_translations(lang))
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return templates.TemplateResponse(
                "admin/list.html",
                {
                    "request": request,
                    "admin_user": None,
                    "nav_user": None,
                    "lang": lang,
                    "t": t,
                    "modules": request.app.state.module_admin_entries,
                    "pages": [],
                    "message": _msg(lang, "admin.no_access", "Admin access required."),
                },
            )
        pages = db.query(CmsPage).order_by(CmsPage.updated_at.desc(), CmsPage.id.desc()).all()
        message = request.query_params.get("message")
        return templates.TemplateResponse(
            "admin/list.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "lang": lang,
                "t": t,
                "modules": request.app.state.module_admin_entries,
                "pages": pages,
                "message": message,
            },
        )
    finally:
        db.close()


@admin_router.get("/new", response_class=HTMLResponse)
def cms_admin_new(request: Request, lang: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang).copy()
        t.update(_get_module_translations(lang))
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        return templates.TemplateResponse(
            "admin/edit.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "lang": lang,
                "t": t,
                "modules": request.app.state.module_admin_entries,
                "page": None,
                "allowed_roles": [],
                "message": request.query_params.get("message"),
            },
        )
    finally:
        db.close()


@admin_router.get("/{page_id}", response_class=HTMLResponse)
def cms_admin_edit(request: Request, lang: str, page_id: int):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang).copy()
        t.update(_get_module_translations(lang))
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module",
                _msg(lang, "cms.msg.not_found", "Page not found"),
            )
        return templates.TemplateResponse(
            "admin/edit.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "lang": lang,
                "t": t,
                "modules": request.app.state.module_admin_entries,
                "page": page,
                "allowed_roles": _parse_roles(page.allowed_roles),
                "message": request.query_params.get("message"),
            },
        )
    finally:
        db.close()


@admin_router.get("/{page_id}/preview", response_class=HTMLResponse)
def cms_admin_preview(request: Request, lang: str, page_id: int):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        t = get_translations(lang).copy()
        t.update(_get_module_translations(lang))
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module",
                _msg(lang, "cms.msg.not_found", "Page not found"),
            )
        return templates.TemplateResponse(
            "admin/preview.html",
            {
                "request": request,
                "admin_user": admin_user,
                "nav_user": admin_user,
                "lang": lang,
                "t": t,
                "modules": request.app.state.module_admin_entries,
                "page": page,
            },
        )
    finally:
        db.close()


@admin_router.post("/create")
def cms_admin_create(
    request: Request,
    lang: str,
    slug: str = Form(...),
    page_lang: str = Form(..., alias="page_lang"),
    title: str = Form(...),
    content_html: str = Form(...),
    access_level: str = Form(default=CmsAccessLevel.PUBLIC.value),
    allowed_roles: list[str] = Form(default=[]),
    is_published: bool = Form(default=False),
    is_root: bool = Form(default=False),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        page_lang = normalize_lang(page_lang)
        if _get_page_by_slug(db, page_lang, slug):
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module/new",
                _msg(lang, "cms.msg.slug_exists", "Slug already exists"),
            )
        if access_level not in {level.value for level in CmsAccessLevel}:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module/new",
                _msg(lang, "cms.msg.invalid_access", "Invalid access level"),
            )
        allowed_role_values = _allowed_role_values()
        filtered_roles = [role for role in allowed_roles if role in allowed_role_values]
        if access_level == CmsAccessLevel.ROLE.value and not filtered_roles:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module/new",
                _msg(lang, "cms.msg.roles_required", "Roles required"),
            )
        page = CmsPage(
            slug=slug.strip(),
            lang=page_lang,
            title=title.strip(),
            content_html=content_html,
            is_published=is_published,
            is_root=is_root,
            access_level=CmsAccessLevel(access_level),
            allowed_roles=_serialize_roles(filtered_roles),
        )
        db.add(page)
        if is_root:
            _unset_root_for_lang(db, page_lang)
        db.commit()
        return _redirect_with_message(
            lang,
            "/admin_panel/module_cms_module",
            _msg(lang, "cms.msg.created", "Page created"),
        )
    finally:
        db.close()


@admin_router.post("/{page_id}/update")
def cms_admin_update(
    request: Request,
    lang: str,
    page_id: int,
    slug: str = Form(...),
    page_lang: str = Form(..., alias="page_lang"),
    title: str = Form(...),
    content_html: str = Form(...),
    access_level: str = Form(default=CmsAccessLevel.PUBLIC.value),
    allowed_roles: list[str] = Form(default=[]),
    is_published: bool = Form(default=False),
    is_root: bool = Form(default=False),
):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module",
                _msg(lang, "cms.msg.not_found", "Page not found"),
            )
        page_lang = normalize_lang(page_lang)
        existing = _get_page_by_slug(db, page_lang, slug)
        if existing and existing.id != page.id:
            return _redirect_with_message(
                lang,
                f"/admin_panel/module_cms_module/{page_id}",
                _msg(lang, "cms.msg.slug_exists", "Slug already exists"),
            )
        if access_level not in {level.value for level in CmsAccessLevel}:
            return _redirect_with_message(
                lang,
                f"/admin_panel/module_cms_module/{page_id}",
                _msg(lang, "cms.msg.invalid_access", "Invalid access level"),
            )
        allowed_role_values = _allowed_role_values()
        filtered_roles = [role for role in allowed_roles if role in allowed_role_values]
        if access_level == CmsAccessLevel.ROLE.value and not filtered_roles:
            return _redirect_with_message(
                lang,
                f"/admin_panel/module_cms_module/{page_id}",
                _msg(lang, "cms.msg.roles_required", "Roles required"),
            )
        page.slug = slug.strip()
        page.lang = page_lang
        page.title = title.strip()
        page.content_html = content_html
        page.is_published = is_published
        page.is_root = is_root
        page.access_level = CmsAccessLevel(access_level)
        page.allowed_roles = _serialize_roles(filtered_roles)
        if is_root:
            _unset_root_for_lang(db, page_lang, current_id=page.id)
        db.add(page)
        db.commit()
        return _redirect_with_message(
            lang,
            "/admin_panel/module_cms_module",
            _msg(lang, "cms.msg.updated", "Page updated"),
        )
    finally:
        db.close()


@admin_router.post("/{page_id}/delete")
def cms_admin_delete(request: Request, lang: str, page_id: int):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        admin_user = _require_admin_user(request, db)
        if not admin_user:
            return _redirect_with_message(
                lang,
                "/admin_panel/",
                _msg(lang, "admin.no_access", "Admin access required."),
            )
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            return _redirect_with_message(
                lang,
                "/admin_panel/module_cms_module",
                _msg(lang, "cms.msg.not_found", "Page not found"),
            )
        db.delete(page)
        db.commit()
        return _redirect_with_message(
            lang,
            "/admin_panel/module_cms_module",
            _msg(lang, "cms.msg.deleted", "Page deleted"),
        )
    finally:
        db.close()


@api_router.get("/pages/{lang}/{slug}")
def cms_api_get_page(request: Request, lang: str, slug: str):
    db = next(get_db())
    try:
        lang = normalize_lang(lang)
        page = _get_published_page(db, lang, slug)
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        user = _get_api_user_optional(request, db)
        if not _page_allows_user(page, user):
            if not user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            raise HTTPException(status_code=403, detail="Forbidden")
        return {
            "id": page.id,
            "slug": page.slug,
            "lang": page.lang,
            "title": page.title,
            "content_html": page.content_html,
            "access_level": page.access_level.value,
            "allowed_roles": _parse_roles(page.allowed_roles),
            "is_published": page.is_published,
            "is_root": page.is_root,
        }
    finally:
        db.close()


@api_router.get("/pages")
def cms_api_list_pages(request: Request):
    db = next(get_db())
    try:
        user = _get_api_user_optional(request, db)
        if not user or user.role not in ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Forbidden")
        pages = db.query(CmsPage).order_by(CmsPage.updated_at.desc(), CmsPage.id.desc()).all()
        return [
            {
                "id": page.id,
                "slug": page.slug,
                "lang": page.lang,
                "title": page.title,
                "content_html": page.content_html,
                "access_level": page.access_level.value,
                "allowed_roles": _parse_roles(page.allowed_roles),
                "is_published": page.is_published,
                "is_root": page.is_root,
            }
            for page in pages
        ]
    finally:
        db.close()


@api_router.post("/pages")
def cms_api_create_page(payload: CmsPageCreate, request: Request):
    db = next(get_db())
    try:
        user = _get_api_user_optional(request, db)
        if not user or user.role not in ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Forbidden")
        lang = normalize_lang(payload.lang)
        if _get_page_by_slug(db, lang, payload.slug):
            raise HTTPException(status_code=400, detail="Slug already exists")
        allowed_role_values = _allowed_role_values()
        filtered_roles = [role for role in payload.allowed_roles if role in allowed_role_values]
        if payload.access_level == CmsAccessLevel.ROLE and not filtered_roles:
            raise HTTPException(status_code=400, detail="Roles required")
        page = CmsPage(
            slug=payload.slug.strip(),
            lang=lang,
            title=payload.title.strip(),
            content_html=payload.content_html,
            is_published=payload.is_published,
            is_root=payload.is_root,
            access_level=payload.access_level,
            allowed_roles=_serialize_roles(filtered_roles),
        )
        db.add(page)
        if payload.is_root:
            _unset_root_for_lang(db, page.lang)
        db.commit()
        return {"id": page.id}
    finally:
        db.close()


@api_router.put("/pages/{page_id}")
def cms_api_update_page(payload: CmsPageUpdate, request: Request, page_id: int):
    db = next(get_db())
    try:
        user = _get_api_user_optional(request, db)
        if not user or user.role not in ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Forbidden")
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        lang = normalize_lang(payload.lang)
        existing = _get_page_by_slug(db, lang, payload.slug)
        if existing and existing.id != page.id:
            raise HTTPException(status_code=400, detail="Slug already exists")
        allowed_role_values = _allowed_role_values()
        filtered_roles = [role for role in payload.allowed_roles if role in allowed_role_values]
        if payload.access_level == CmsAccessLevel.ROLE and not filtered_roles:
            raise HTTPException(status_code=400, detail="Roles required")
        page.slug = payload.slug.strip()
        page.lang = lang
        page.title = payload.title.strip()
        page.content_html = payload.content_html
        page.is_published = payload.is_published
        page.is_root = payload.is_root
        page.access_level = payload.access_level
        page.allowed_roles = _serialize_roles(filtered_roles)
        if payload.is_root:
            _unset_root_for_lang(db, page.lang, current_id=page.id)
        db.add(page)
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@api_router.delete("/pages/{page_id}")
def cms_api_delete_page(request: Request, page_id: int):
    db = next(get_db())
    try:
        user = _get_api_user_optional(request, db)
        if not user or user.role not in ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Forbidden")
        page = db.query(CmsPage).filter(CmsPage.id == page_id).first()
        if not page:
            raise HTTPException(status_code=404, detail="Page not found")
        db.delete(page)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()


def root_handler(request: Request) -> Response | None:
    db = next(get_db())
    try:
        lang = _preferred_lang(request)
        page = _get_root_page(db, lang)
        if not page:
            return None
        return _render_page_response(request, db, lang, page)
    finally:
        db.close()


def get_module():
    return {
        "name": "cms_module",
        "routers": [cms_router, admin_router, api_router],
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
