"""Distro packages (purl types ``deb``, ``rpm``, ``apk``) as OSV asks about them.

OSV keys its distribution ecosystems by SOURCE package and by release: Debian's
``glibc`` in ``Debian:12``, not the binary ``libc6``. An SBOM lists binary
packages, and core keys a component by its purl with every qualifier dropped
(``pkg:deb/debian/libc6@2.36-9+deb12u7``), so the release and the source
package are known only where the SBOM states them, which ``sbom.components``
reads. This module turns one SBOM entry into the OSV package it is asked as,
``ECOSYSTEM|NAME|VERSION`` (``osv_package``), or the reason it cannot be:

| purl | ecosystem |
|---|---|
| ``pkg:deb/debian/...?distro=debian-12`` (or ``bookworm``) | ``Debian:12`` |
| ``pkg:deb/ubuntu/...?distro=ubuntu-22.04`` | ``Ubuntu:22.04`` |
| ``pkg:apk/alpine/...?distro=alpine-3.19.1`` | ``Alpine:v3.19`` |
| ``pkg:apk/wolfi/...`` | ``Wolfi`` |
| ``pkg:apk/chainguard/...`` | ``Chainguard`` |
| ``pkg:rpm/redhat/...`` | ``Red Hat`` |
| ``pkg:rpm/rocky/...?distro=rocky-9.3`` | ``Rocky Linux:9`` |
| ``pkg:rpm/almalinux/...?distro=almalinux-9.3`` | ``AlmaLinux:9`` |

The source package comes from, in order: the purl's ``upstream`` qualifier
(Syft: ``glibc``, ``glibc@2.36-9``, ``glibc-2.34-60.el9.src.rpm``), the
component's properties (Syft ``syft:package:metadata:source`` /
``sourceVersion``, also spelled ``syft:metadata:...``; Trivy
``aquasecurity:trivy:SrcName`` / ``SrcVersion`` / ``SrcRelease`` / ``SrcEpoch``),
or an SPDX package's ``sourceInfo`` (Trivy: ``built package from: glibc
2.36-9+deb12u7``). The source version is the one stated with it, else the
binary version (Debian: less a binNMU ``+bN`` suffix, which only binaries carry;
RPM: with the ``epoch`` qualifier as ``E:``). A Syft SBOM states a deb or apk
source only when it differs from the binary name (as dpkg and apk do), so there
an entry with none is its own source (``binary_is_source``).

Nothing is guessed: a binary name is never taken for its source name, and an
unknown distribution or release never becomes an ecosystem. Such an entry
carries ``osv_unmapped`` with its reason (``no_distro_qualifier``,
``unknown_distro``, ``no_source_package``, ``no_version``) and stays "not
checked" downstream, never clean.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote

DISTRO_TYPES: Final = frozenset({"deb", "rpm", "apk"})
#: Debian codenames OSV and SBOM tools spell a release by (a fixed table, never inferred).
DEBIAN_CODENAMES: Final = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
UNMAPPED_REASONS: Final = (
    "no_distro_qualifier",
    "no_source_package",
    "no_version",
    "unknown_distro",
)
# The release in the ``distro`` qualifier: Syft writes ``debian-12``, Trivy
# ``debian-12.4`` or, for Alpine, the bare ``3.19.1`` (the namespace already names
# the distribution, so a bare release is unambiguous there).
_DEBIAN = re.compile(r"^(?:debian-)?(\d+)(?:\.\d+)*$")
_UBUNTU = re.compile(r"^(?:ubuntu-)?(\d\d\.\d\d)(?:\.\d+)?$")
_ALPINE = re.compile(r"^(?:alpine-)?(\d+)\.(\d+)(?:\.\d+)*$")
_ROCKY = re.compile(r"^(?:rocky(?:-linux)?-)?(\d+)(?:\.\d+)*$")
_ALMA = re.compile(r"^(?:almalinux-)?(\d+)(?:\.\d+)*$")
_SRC_RPM = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)\.src\.rpm$")
_BUILT_FROM = re.compile(r"^built package from:\s*(?P<name>\S+)(?:\s+(?P<version>\S+))?\s*$")
_BINNMU = re.compile(r"\+b\d+$")
#: The longest ``osv_package`` text (the SBOM row Contract's bound too).
MAX_PACKAGE_TEXT: Final = 256


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: Mapping[str, str]


def parse(text: str) -> Purl | None:
    """A purl's parts, percent-decoded; ``None`` for text that is no ``pkg:`` purl."""

    if not text.startswith("pkg:"):
        return None
    body = text[4:].split("#", 1)[0]
    body, _, query = body.partition("?")
    qualifiers: dict[str, str] = {}
    for pair in query.split("&") if query else ():
        key, _, value = pair.partition("=")
        if key:
            qualifiers[key.lower()] = unquote(value)
    path, version = body, ""
    if "@" in body.rsplit("/", 1)[-1]:
        path, _, version = body.rpartition("@")
    parts = [unquote(part) for part in path.strip("/").split("/")]
    if len(parts) < 2:
        return None
    return Purl(
        type=parts[0].lower(),
        namespace="/".join(parts[1:-1]).lower(),
        name=parts[-1],
        version=unquote(version),
        qualifiers=qualifiers,
    )


def ecosystem(purl: Purl) -> tuple[str | None, str | None]:
    """(OSV ecosystem, None) for a distro purl OSV keys, else (None, reason)."""

    distro = purl.qualifiers.get("distro", "").lower()
    if purl.type == "deb":
        if purl.namespace == "debian":
            if not distro:
                return None, "no_distro_qualifier"
            match = _DEBIAN.fullmatch(distro)
            release = match.group(1) if match else DEBIAN_CODENAMES.get(distro)
            return (f"Debian:{release}", None) if release else (None, "unknown_distro")
        if purl.namespace == "ubuntu":
            if not distro:
                return None, "no_distro_qualifier"
            match = _UBUNTU.fullmatch(distro)
            return (f"Ubuntu:{match.group(1)}", None) if match else (None, "unknown_distro")
    if purl.type == "apk":
        if purl.namespace == "wolfi":
            return "Wolfi", None
        if purl.namespace == "chainguard":
            return "Chainguard", None
        if purl.namespace == "alpine":
            if not distro:
                return None, "no_distro_qualifier"
            match = _ALPINE.fullmatch(distro)
            return (
                (f"Alpine:v{match.group(1)}.{match.group(2)}", None)
                if match
                else (None, "unknown_distro")
            )
    if purl.type == "rpm":
        if purl.namespace == "redhat":
            return "Red Hat", None
        for namespaces, pattern, name in (
            (("rocky", "rocky-linux"), _ROCKY, "Rocky Linux"),
            (("almalinux",), _ALMA, "AlmaLinux"),
        ):
            if purl.namespace in namespaces:
                if not distro:
                    return None, "no_distro_qualifier"
                match = pattern.fullmatch(distro)
                return (f"{name}:{match.group(1)}", None) if match else (None, "unknown_distro")
    return None, "unknown_distro"


def _property(properties: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = properties.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _source(
    purl: Purl, properties: Mapping[str, str], source_info: str | None
) -> tuple[str | None, str | None]:
    """(source package name, its version if the SBOM states one)."""

    upstream = purl.qualifiers.get("upstream", "").strip()
    if upstream:
        if purl.type == "rpm":
            match = _SRC_RPM.fullmatch(upstream)
            if match:
                return match["name"], f"{match['version']}-{match['release']}"
            return upstream.removesuffix(".src.rpm"), None
        name, _, version = upstream.partition("@")
        return name, (version or None)
    name = _property(
        properties,
        "syft:package:metadata:source",
        "syft:metadata:source",
        "aquasecurity:trivy:SrcName",
    )
    if name:
        version = _property(
            properties, "syft:package:metadata:sourceVersion", "syft:metadata:sourceVersion"
        )
        trivy = _property(properties, "aquasecurity:trivy:SrcVersion")
        if version is None and trivy:
            release = _property(properties, "aquasecurity:trivy:SrcRelease")
            epoch = _property(properties, "aquasecurity:trivy:SrcEpoch")
            version = trivy + (f"-{release}" if release else "")
            if epoch and epoch != "0":
                version = f"{epoch}:{version}"
        return name, version
    match = _BUILT_FROM.fullmatch(source_info or "")
    if match:
        return match["name"], match["version"]
    return None, None


def osv_package(
    text: str,
    *,
    properties: Mapping[str, str] | None = None,
    source_info: str | None = None,
    binary_is_source: bool = False,
) -> tuple[str | None, str | None]:
    """(``ECOSYSTEM|NAME|VERSION``, None) for a distro entry OSV can be asked about by
    source package, else (None, reason). Only for purl types ``deb``, ``rpm``, ``apk``.

    ``binary_is_source`` is for an SBOM whose generator states a deb or apk
    package's source only when it differs from the binary (Syft: dpkg's
    ``Source`` and apk's origin fields are written only then): there an entry
    with no source stated is its own source. Any other generator's entry with no
    source stated is ``no_source_package``.
    """

    purl = parse(text)
    if purl is None or purl.type not in DISTRO_TYPES:
        return None, "unknown_distro"
    found, reason = ecosystem(purl)
    if found is None:
        return None, reason
    name, version = _source(purl, properties or {}, source_info)
    if not name and binary_is_source and purl.type in ("deb", "apk"):
        name = purl.name
    if not name:
        return None, "no_source_package"
    if not version:
        version = purl.version
        if purl.type == "deb":
            version = _BINNMU.sub("", version)
    if not version:
        return None, "no_version"
    epoch = purl.qualifiers.get("epoch", "")
    if purl.type == "rpm" and epoch and epoch != "0" and ":" not in version:
        version = f"{epoch}:{version}"
    package = f"{found}|{name}|{version}"
    if "|" in name or "|" in version or len(package) > MAX_PACKAGE_TEXT:
        return None, "no_source_package"
    return package, None


def split(package: str) -> tuple[str, str, str]:
    """``ECOSYSTEM|NAME|VERSION`` as its three parts (``ValueError`` otherwise)."""

    parts = package.split("|")
    if len(parts) != 3 or not all(parts):
        raise ValueError(f"not an OSV package (ECOSYSTEM|NAME|VERSION): {package!r}")
    return parts[0], parts[1], parts[2]
