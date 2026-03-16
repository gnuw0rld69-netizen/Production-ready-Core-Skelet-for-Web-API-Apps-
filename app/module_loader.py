from __future__ import annotations

from dataclasses import dataclass
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Callable
import importlib
import sys

from fastapi import APIRouter
from sqlalchemy import MetaData


@dataclass(frozen=True)
class ModuleInfo:
    name: str
    routers: list[APIRouter]
    templates_dir: Path | None
    metadata: list[MetaData]
    admin_entry: dict[str, str] | None
    root_handler: Callable[..., Any] | None


def _load_module_from_path(module_path: Path):
    package_name = f"modules.{module_path.parent.name}"
    module_name = f"{package_name}.module"
    importlib.import_module(package_name)
    spec = spec_from_file_location(module_name, module_path)
    if not spec or not spec.loader:
        return None
    module = module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _normalize_module_data(raw: dict[str, Any], module_path: Path) -> ModuleInfo:
    name = raw.get("name") or module_path.parent.name
    routers = list(raw.get("routers", []))
    templates_dir = raw.get("templates_dir")
    metadata_items = raw.get("metadata", [])
    admin_entry = raw.get("admin_entry")
    root_handler = raw.get("root_handler")

    if templates_dir is not None:
        templates_dir = Path(templates_dir)

    if not isinstance(metadata_items, list):
        metadata_items = [metadata_items]

    normalized_metadata: list[MetaData] = []
    for item in metadata_items:
        if isinstance(item, MetaData):
            normalized_metadata.append(item)

    if admin_entry:
        admin_entry = {
            "name": admin_entry.get("name", name),
            "label": admin_entry.get("label", name),
            "path": admin_entry.get("path", f"/admin_panel/module_{name}"),
        }

    return ModuleInfo(
        name=name,
        routers=routers,
        templates_dir=templates_dir,
        metadata=normalized_metadata,
        admin_entry=admin_entry,
        root_handler=root_handler,
    )


def load_modules(modules_dir: Path) -> list[ModuleInfo]:
    if not modules_dir.exists():
        return []

    module_infos: list[ModuleInfo] = []
    for module_path in sorted(modules_dir.glob("*/module.py")):
        module = _load_module_from_path(module_path)
        if module is None:
            continue
        if hasattr(module, "get_module"):
            raw = module.get_module()
        else:
            raw = getattr(module, "MODULE", None)
        if not isinstance(raw, dict):
            continue
        module_infos.append(_normalize_module_data(raw, module_path))

    return module_infos
