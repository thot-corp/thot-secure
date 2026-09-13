"""Console web embarquée (Jinja2 + JavaScript natif, aucun build Node requis)."""

from __future__ import annotations

from .routes import COOKIE_NAME, STATIC_DIR, TEMPLATES_DIR, build_ui_router

__all__ = ["COOKIE_NAME", "STATIC_DIR", "TEMPLATES_DIR", "build_ui_router"]
