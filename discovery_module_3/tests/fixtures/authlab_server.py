#!/usr/bin/env python3
"""Internal HTTP fixture for authentication discovery tests.

The service is intended only for testing AuthPoints on the same machine.  It
does not persist credentials; POST handlers accept only fixed demo values and
record method counters so GET-only behaviour can be verified.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import json
import socketserver
import threading
from collections import Counter
from dataclasses import dataclass, field
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


PROFILES = {
    "portal": 8080,
    "admin": 8081,
    "identity": 8082,
    "legacy": 8083,
    "api": 8084,
}
TCP_PROFILES = {
    "ftp": 2121,
    "ssh": 2222,
}
DEMO_USERNAME = "student"
DEMO_PASSWORD = "password123"


@dataclass
class LabState:
    """Only aggregate request counters are retained; request bodies are never logged."""

    counters: Counter[str] = field(default_factory=Counter)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, method: str, profile: str) -> None:
        with self.lock:
            self.counters[method.upper()] += 1
            self.counters[f"{profile}:{method.upper()}"] += 1

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(sorted(self.counters.items()))


class AuthLabServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        profile: str,
        public_host: str,
        state: LabState,
        demo_username: str,
        demo_password: str,
    ) -> None:
        self.profile = profile
        self.public_host = public_host
        self.state = state
        self.demo_username = demo_username
        self.demo_password = demo_password
        super().__init__(address, AuthLabHandler)


def create_server(
    profile: str,
    *,
    bind: str = "127.0.0.1",
    port: int | None = None,
    public_host: str = "127.0.0.1",
    state: LabState | None = None,
    demo_username: str = DEMO_USERNAME,
    demo_password: str = DEMO_PASSWORD,
) -> AuthLabServer:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    return AuthLabServer(
        (bind, PROFILES[profile] if port is None else port),
        profile=profile,
        public_host=public_host,
        state=state or LabState(),
        demo_username=demo_username,
        demo_password=demo_password,
    )


class AuthLabTCPServer(socketserver.ThreadingTCPServer):
    """Small protocol stubs used only to let Nmap identify SSH and FTP."""

    allow_reuse_address = True
    daemon_threads = True


class SSHLabHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2)
        self.request.sendall(b"SSH-2.0-OpenSSH_9.6p1 AuthPointsLab\r\n")
        try:
            # A client may answer with its identification string. It is discarded.
            self.request.recv(1024)
        except OSError:
            pass


class FTPLabHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2)
        self.request.sendall(b"220 ProFTPD 1.3.7 Server (AuthPointsLab)\r\n")
        buffer = b""
        for _ in range(8):
            try:
                chunk = self.request.recv(1024)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                command = line.strip().split(b" ", 1)[0].upper()
                if command == b"SYST":
                    reply = b"215 UNIX Type: L8\r\n"
                elif command == b"FEAT":
                    reply = b"211-Features\r\n UTF8\r\n211 End\r\n"
                elif command == b"USER":
                    reply = b"331 Password required\r\n"
                elif command == b"PASS":
                    reply = b"530 Authentication incorrect\r\n"
                elif command == b"QUIT":
                    self.request.sendall(b"221 Goodbye\r\n")
                    return
                else:
                    reply = b"500 Command not understood\r\n"
                self.request.sendall(reply)


def create_tcp_server(
    profile: str,
    *,
    bind: str = "127.0.0.1",
    port: int | None = None,
) -> AuthLabTCPServer:
    handlers = {"ftp": FTPLabHandler, "ssh": SSHLabHandler}
    if profile not in TCP_PROFILES:
        raise ValueError(f"unknown TCP profile: {profile}")
    return AuthLabTCPServer(
        (bind, TCP_PROFILES[profile] if port is None else port),
        handlers[profile],
    )


class AuthLabHandler(BaseHTTPRequestHandler):
    server: AuthLabServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self.server.state.record("GET", self.server.profile)
        path = urlsplit(self.path).path
        if path == "/lab/telemetry":
            self._json(HTTPStatus.OK, {"requests": self.server.state.snapshot()})
            return
        self._dispatch_get(path)

    def do_POST(self) -> None:  # noqa: N802
        self.server.state.record("POST", self.server.profile)
        path = urlsplit(self.path).path
        if path not in {
            "/session",
            "/admin/session",
            "/legacy/session",
            "/oauth/authorize",
            "/saml/login",
            "/adfs/ls",
            "/api/auth/login",
        }:
            self._method_not_allowed()
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(min(length, 16 * 1024))
        content_type = self.headers.get("Content-Type", "")
        try:
            values = json.loads(body.decode("utf-8")) if "json" in content_type else parse_qs(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            values = {}
        username = self._field(values, "username", "email", "login")
        password = self._field(values, "password")
        if hmac.compare_digest(username, self.server.demo_username) and hmac.compare_digest(
            password,
            self.server.demo_password,
        ):
            self._redirect("/dashboard")
        else:
            self._html(HTTPStatus.UNAUTHORIZED, "Login rejected", "<h1>Invalid lab credentials</h1>")

    def do_PUT(self) -> None:  # noqa: N802
        self.server.state.record("PUT", self.server.profile)
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self.server.state.record("DELETE", self.server.profile)
        self._method_not_allowed()

    def _dispatch_get(self, path: str) -> None:
        routes = {
            "portal": self._portal,
            "admin": self._admin,
            "identity": self._identity,
            "legacy": self._legacy,
            "api": self._api,
        }
        routes[self.server.profile](path)

    def _portal(self, path: str) -> None:
        if path == "/":
            self._html(
                HTTPStatus.OK,
                "Customer Portal",
                """
                <h1>Customer portal</h1>
                <nav>
                  <a href="/login">Sign in</a>
                  <a href="/signin">Continue with email</a>
                  <a href="/account/login">Account login</a>
                  <a href="/js-app">JavaScript login</a>
                  <a href="/private">Private dashboard</a>
                  <a href="/register">Create account</a>
                  <a href="/reset-password">Forgot password</a>
                  <a href="/robots.txt">robots.txt</a>
                  <a href="/sitemap.xml">sitemap.xml</a>
                  <a href="/oidc/start">Company SSO</a>
                  <a href="{admin}/admin/login">Admin console</a>
                  <a href="{identity}/oauth/authorize?client_id=authpoints-lab&amp;response_type=code&amp;redirect_uri={portal}/oidc/callback">Identity provider</a>
                  <a href="{legacy}/users/sign_in">Legacy application</a>
                  <a href="{api}/api/private">Private API</a>
                </nav>
                """.format(**self._origins()),
            )
        elif path in {"/login", "/account/login"}:
            self._login_form("Portal login", "/session", "username")
        elif path == "/signin":
            self._html(
                HTTPStatus.OK,
                "Continue to sign in",
                """
                <h1>Sign in</h1>
                <form action="/login" method="get">
                  <label>Email <input name="email" autocomplete="username"></label>
                  <button type="submit">Continue</button>
                </form>
                """,
            )
        elif path == "/js-app":
            self._html(
                HTTPStatus.OK,
                "JavaScript application",
                """
                <h1>JavaScript application</h1>
                <div id="login-root"></div>
                <script>
                  document.addEventListener("DOMContentLoaded", () => {
                    const form = document.createElement("form");
                    form.action = "/session";
                    form.method = "post";
                    const username = document.createElement("input");
                    username.name = "username";
                    username.autocomplete = "username";
                    const password = document.createElement("input");
                    password.name = "password";
                    password.type = "password";
                    password.autocomplete = "current-password";
                    const submit = document.createElement("button");
                    submit.type = "submit";
                    submit.textContent = "Sign in";
                    form.append(username, password, submit);
                    document.getElementById("login-root").append(form);
                  });
                </script>
                """,
            )
        elif path == "/private":
            self._redirect("/login")
        elif path == "/oidc/start":
            self._redirect(
                self._origin("identity")
                + "/oauth/authorize?client_id=authpoints-lab&response_type=code&redirect_uri="
                + self._origin("portal")
                + "/oidc/callback"
            )
        elif path == "/oidc/callback":
            self._html(HTTPStatus.BAD_REQUEST, "OIDC callback", "<h1>Callback endpoint</h1>")
        elif path == "/register":
            self._registration_form()
        elif path == "/reset-password":
            self._html(
                HTTPStatus.OK,
                "Reset password",
                "<h1>Reset password</h1><form><input name='email'><button>Send reset link</button></form>",
            )
        elif path == "/logout":
            self._html(HTTPStatus.OK, "Logged out", "<h1>You are logged out</h1>")
        elif path == "/robots.txt":
            self._text("User-agent: *\nAllow: /login\nAllow: /account/login\nSitemap: /sitemap.xml\n")
        elif path == "/sitemap.xml":
            origin = self._origin("portal")
            self._xml(
                "<?xml version='1.0' encoding='UTF-8'?>"
                "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                f"<url><loc>{origin}/login</loc></url>"
                f"<url><loc>{origin}/account/login</loc></url>"
                "</urlset>"
            )
        elif path == "/dashboard":
            self._html(HTTPStatus.OK, "Dashboard", "<h1>Lab dashboard</h1>")
        else:
            self._not_found(path)

    def _admin(self, path: str) -> None:
        if path in {"/", "/admin"}:
            self._html(
                HTTPStatus.OK,
                "Administration",
                "<h1>Administration</h1><a href='/admin/login'>Admin login</a> "
                "<a href='/admin/basic'>HTTP Basic panel</a> <a href='/admin/forbidden'>Restricted page</a>",
            )
        elif path == "/admin/login":
            self._login_form("Administration login", "/admin/session", "email")
        elif path == "/admin/basic":
            self._basic_auth_page("AuthPoints Lab Admin", "Admin Basic dashboard")
        elif path == "/admin/forbidden":
            self._html(HTTPStatus.FORBIDDEN, "Forbidden", "<h1>Access denied</h1>")
        elif path == "/dashboard":
            self._html(HTTPStatus.OK, "Admin dashboard", "<h1>Admin dashboard</h1>")
        else:
            self._not_found(path)

    def _identity(self, path: str) -> None:
        if path == "/":
            self._html(
                HTTPStatus.OK,
                "Identity service",
                """
                <h1>Identity service</h1>
                <a href="/oauth/authorize?client_id=authpoints-lab&amp;response_type=code&amp;redirect_uri={portal}/oidc/callback">OAuth authorize</a>
                <a href="/saml/login">SAML login</a>
                <a href="/adfs/ls">ADFS login</a>
                <a href="/.well-known/openid-configuration">OpenID metadata</a>
                <a href="/oauth/token">Token endpoint</a>
                """.format(**self._origins()),
            )
        elif path in {"/oauth/authorize", "/saml/login", "/adfs/ls"}:
            self._login_form("Identity provider sign in", path, "username")
        elif path == "/.well-known/openid-configuration":
            origin = self._origin("identity")
            self._json(
                HTTPStatus.OK,
                {
                    "issuer": origin,
                    "authorization_endpoint": origin + "/oauth/authorize",
                    "token_endpoint": origin + "/oauth/token",
                    "jwks_uri": origin + "/oauth/jwks.json",
                },
            )
        elif path in {"/oauth/token", "/oauth/userinfo", "/oauth/jwks.json", "/oauth/callback"}:
            self._json(HTTPStatus.OK, {"lab": "not an interactive login endpoint"})
        elif path == "/dashboard":
            self._html(HTTPStatus.OK, "Identity dashboard", "<h1>Identity dashboard</h1>")
        else:
            self._not_found(path)

    def _legacy(self, path: str) -> None:
        if path == "/":
            self._html(
                HTTPStatus.OK,
                "Legacy systems",
                """
                <h1>Legacy systems</h1>
                <a href="/users/sign_in">Rails sign in</a>
                <a href="/wp-login.php">WordPress login</a>
                <a href="/remote/login">Remote access login</a>
                <a href="/owa/auth/logon.aspx">Webmail login</a>
                """,
            )
        elif path in {"/users/sign_in", "/wp-login.php", "/remote/login", "/owa/auth/logon.aspx"}:
            self._login_form("Legacy login", "/legacy/session", "login")
        elif path == "/dashboard":
            self._html(HTTPStatus.OK, "Legacy dashboard", "<h1>Legacy dashboard</h1>")
        else:
            self._not_found(path)

    def _api(self, path: str) -> None:
        if path == "/":
            self._html(
                HTTPStatus.OK,
                "API gateway",
                "<h1>API gateway</h1><a href='/api/private'>Bearer API</a> "
                "<a href='/api/basic'>Basic API</a> <a href='/api/auth/login'>API login</a>",
            )
        elif path == "/api/private":
            self._json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "authentication_required"},
                {"WWW-Authenticate": 'Bearer realm="AuthPoints Lab API"'},
            )
        elif path == "/api/basic":
            if self._has_valid_basic_credentials():
                self._json(HTTPStatus.OK, {"message": "authenticated lab request"})
            else:
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "authentication_required"},
                    {"WWW-Authenticate": 'Basic realm="AuthPoints Lab API"'},
                )
        elif path == "/api/auth/login":
            self._json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"message": "Use POST with JSON credentials in the local lab"},
                {"Allow": "POST"},
            )
        elif path == "/dashboard":
            self._json(HTTPStatus.OK, {"message": "lab dashboard"})
        else:
            self._not_found(path)

    def _login_form(self, title: str, action: str, identifier: str) -> None:
        self._html(
            HTTPStatus.OK,
            title,
            f"""
            <h1>{escape(title)}</h1>
            <form action="{escape(action, quote=True)}" method="post">
              <label>Username <input name="{escape(identifier, quote=True)}" autocomplete="username"></label>
              <label>Password <input type="password" name="password" autocomplete="current-password"></label>
              <button type="submit">Sign in</button>
            </form>
            """,
        )

    def _registration_form(self) -> None:
        self._html(
            HTTPStatus.OK,
            "Create account",
            """
            <h1>Create account</h1>
            <form action="/register" method="post">
              <input name="email" autocomplete="email">
              <input type="password" name="password" autocomplete="new-password">
              <input type="password" name="confirm_password" autocomplete="new-password">
              <button>Create account</button>
            </form>
            """,
        )

    def _basic_auth_page(self, realm: str, title: str) -> None:
        if self._has_valid_basic_credentials():
            self._html(HTTPStatus.OK, title, f"<h1>{escape(title)}</h1>")
            return
        self._html(
            HTTPStatus.UNAUTHORIZED,
            "Authentication required",
            "<h1>Authentication required</h1>",
            {"WWW-Authenticate": f'Basic realm="{realm}"'},
        )

    def _has_valid_basic_credentials(self) -> bool:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.casefold() != "basic" or not token:
            return False
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        username, separator, password = decoded.partition(":")
        return bool(separator) and hmac.compare_digest(
            username,
            self.server.demo_username,
        ) and hmac.compare_digest(password, self.server.demo_password)

    def _origins(self) -> dict[str, str]:
        return {profile: self._origin(profile) for profile in PROFILES}

    def _origin(self, profile: str) -> str:
        return f"http://{self.server.public_host}:{PROFILES[profile]}"

    @staticmethod
    def _field(values: object, *names: str) -> str:
        if not isinstance(values, dict):
            return ""
        for name in names:
            value = values.get(name)
            if isinstance(value, list):
                value = value[0] if value else ""
            if isinstance(value, str):
                return value
        return ""

    def _method_not_allowed(self) -> None:
        self._html(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed", "<h1>Method not allowed</h1>", {"Allow": "GET, POST"})

    def _not_found(self, path: str) -> None:
        if path.startswith("/soft404/"):
            self._html(HTTPStatus.OK, "Application", "<h1>Application page</h1><p>Generic route</p>")
        else:
            self._html(HTTPStatus.NOT_FOUND, "Not found", "<h1>Not found</h1>")

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _text(self, text: str) -> None:
        self._send(HTTPStatus.OK, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _xml(self, text: str) -> None:
        self._send(HTTPStatus.OK, text.encode("utf-8"), "application/xml; charset=utf-8")

    def _json(
        self,
        status: HTTPStatus,
        value: object,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._send(status, json.dumps(value).encode("utf-8"), "application/json; charset=utf-8", headers)

    def _html(
        self,
        status: HTTPStatus,
        title: str,
        body: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        document = f"<!doctype html><html><head><title>{escape(title)}</title></head><body>{body}</body></html>"
        self._send(status, document.encode("utf-8"), "text/html; charset=utf-8", headers)

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        # Avoid logging request paths or request bodies in a credentials-oriented lab.
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local AuthPoints training lab")
    parser.add_argument("--bind", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    parser.add_argument("--public-host", default="127.0.0.1", help="Hostname emitted in cross-service links")
    parser.add_argument("--username", default=DEMO_USERNAME, help="Accepted demo username")
    parser.add_argument("--password", default=DEMO_PASSWORD, help="Accepted demo password")
    args = parser.parse_args()

    for option, value in (("--username", args.username), ("--password", args.password)):
        if not value or any(character in value for character in ("\r", "\n", "\x00")):
            parser.error(f"{option} must be non-empty and contain no CR, LF or NUL")

    state = LabState()
    http_servers = [
        create_server(
            profile,
            bind=args.bind,
            public_host=args.public_host,
            state=state,
            demo_username=args.username,
            demo_password=args.password,
        )
        for profile in PROFILES
    ]
    tcp_servers = [
        create_tcp_server(profile, bind=args.bind)
        for profile in TCP_PROFILES
    ]
    servers = [*http_servers, *tcp_servers]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    print("AuthPoints training lab is running:")
    for profile, port in PROFILES.items():
        print(f"  {profile:8} http://{args.public_host}:{port}/")
    for profile, port in TCP_PROFILES.items():
        print(f"  {profile:8} {profile}://{args.public_host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping training lab...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
