"""End-to-end check against an ephemeral local website, never an external host."""
from __future__ import annotations

import io
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zipfile import ZipFile

import pytest

from logingen import cli


@pytest.mark.skipif(shutil.which("katana") is None, reason="Katana is not installed")
@pytest.mark.parametrize("depth", [1, 2])
def test_katana_crawls_html_and_document_and_respects_page_depth(tmp_path, monkeypatch, depth):
    pytest.importorskip("playwright")
    document = io.BytesIO()
    with ZipFile(document, "w") as archive:
        archive.writestr("word/document.xml", '<doc><p>Анна Смирнова</p><p>anna@example.test</p></doc>')
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/directory/")
                self.end_headers()
                return
            if self.path == "/directory/staff.docx":
                body, content_type = document.getvalue(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            elif self.path == "/directory/":
                body = ('<html><body>Иван Иванов Иванович info@example.test '
                        '<a href="team">Team</a><a href="staff.docx">Document</a></body></html>').encode()
                content_type = "text/html; charset=utf-8"
            else:
                body, content_type = b"<html><body>team@example.test</body></html>", "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO())
    try:
        url = f"http://127.0.0.1:{server.server_port}/start"
        assert cli.main(["-u", url, "--katana-depth", str(depth), "--ignore-robots", "-o", "results"]) == 0
        assert ("/directory/team" in requests) == (depth == 2)
        assert requests.count("/directory/") == 1
        assert "/directory/staff.docx" in requests
        expected = {"info@example.test", "anna@example.test"}
        if depth == 2:
            expected.add("team@example.test")
        assert set((tmp_path / "results/emails.txt").read_text().splitlines()) == expected
        assert "Иванов Иван Иванович" in (tmp_path / "results/fio.txt").read_text()
        assert "Смирнова Анна" in (tmp_path / "results/fio.txt").read_text()
        assert {p.name for p in (tmp_path / "results").iterdir()} == {"fio.txt", "emails.txt"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
