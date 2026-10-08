"""The web.fetch input classifier, as cruxible-provider-web defines it.

Core owns the web.fetch registration and classifies runs itself; a package that
exports the definition still ships a classifier reference, and this is it.
"""

from __future__ import annotations

from cruxible_provider_web.interfaces import classify_web_fetch

__all__ = ["classify_web_fetch"]
