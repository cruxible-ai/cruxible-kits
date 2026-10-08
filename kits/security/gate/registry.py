"""A throwaway OCI distribution registry for the security kit gate.

    python registry.py PORT DATA_DIR CERT KEY

HTTPS on 127.0.0.1 only, no auth. Serves exactly what cruxible's RegistryClient
uses: /v2/, blob HEAD/GET, blob upload (POST, then PUT ?digest=), manifest
PUT/GET by tag or digest, and tags/list. Everything lives under DATA_DIR.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

DATA = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parent / "data"
BLOBS = DATA / "blobs"
REPOS = DATA / "repos"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("registry: " + fmt % args + "\n")

    def _send(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _route(self) -> tuple[str, str, str] | None:
        path = urlsplit(self.path).path
        m = re.fullmatch(r"/v2/(.+)/(blobs|manifests|tags)/(.*)", path)
        if m is None:
            return None
        return m.group(1), m.group(2), unquote(m.group(3))

    def do_GET(self) -> None:  # noqa: N802
        if urlsplit(self.path).path in {"/v2", "/v2/"}:
            return self._send(200, b"{}", {"Content-Type": "application/json"})
        route = self._route()
        if route is None:
            return self._send(404)
        repo, kind, ref = route
        if kind == "blobs":
            blob = BLOBS / ref.replace(":", "_")
            if not blob.is_file():
                return self._send(404)
            return self._send(200, blob.read_bytes(), {"Content-Type": "application/octet-stream",
                                                       "Docker-Content-Digest": ref})
        if kind == "manifests":
            digest = ref if ref.startswith("sha256:") else self._tag(repo, ref)
            blob = None if digest is None else BLOBS / digest.replace(":", "_")
            if blob is None or not blob.is_file():
                return self._send(404)
            return self._send(200, blob.read_bytes(), {"Content-Type": MANIFEST_TYPE,
                                                       "Docker-Content-Digest": digest})
        if kind == "tags" and ref.startswith("list"):
            tags = sorted(self._tags(repo))
            return self._send(200, json.dumps({"name": repo, "tags": tags}).encode(),
                              {"Content-Type": "application/json"})
        return self._send(404)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/?", path)
        self._body()
        if m is None:
            return self._send(404)
        return self._send(202, b"", {"Location": f"/v2/{m.group(1)}/blobs/uploads/{uuid.uuid4()}"})

    def do_PUT(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        body = self._body()
        m = re.fullmatch(r"/v2/(.+)/blobs/uploads/[0-9a-f-]+", parts.path)
        if m is not None:
            expected = parse_qs(parts.query).get("digest", [""])[0]
            if _digest(body) != expected:
                return self._send(400, b"digest mismatch")
            (BLOBS / expected.replace(":", "_")).write_bytes(body)
            return self._send(201, b"", {"Docker-Content-Digest": expected})
        route = self._route()
        if route is None or route[1] != "manifests":
            return self._send(404)
        repo, _kind, ref = route
        digest = _digest(body)
        (BLOBS / digest.replace(":", "_")).write_bytes(body)
        if not ref.startswith("sha256:"):
            tags = REPOS / repo / "tags"
            tags.mkdir(parents=True, exist_ok=True)
            (tags / ref).write_text(digest)
        return self._send(201, b"", {"Docker-Content-Digest": digest})

    def _tag(self, repo: str, tag: str) -> str | None:
        path = REPOS / repo / "tags" / tag
        return path.read_text() if path.is_file() else None

    def _tags(self, repo: str) -> list[str]:
        path = REPOS / repo / "tags"
        return [p.name for p in path.iterdir()] if path.is_dir() else []


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5443
    BLOBS.mkdir(parents=True, exist_ok=True)
    REPOS.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[3], sys.argv[4])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"registry on https://localhost:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
