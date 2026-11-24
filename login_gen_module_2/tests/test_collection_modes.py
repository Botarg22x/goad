from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import Mock
from zipfile import ZipFile

import pytest

from logingen import cli
from logingen.collector import CollectionResult, EmailSourceRecord, PersonSourceRecord, collect_public_data
from logingen.documents import detect_document_type, extract_document_text
from logingen.models import AutoConfig, Person
from logingen.playwright_fetcher import FetchBinaryResponse, FetchResponse
from logingen.search_sources import SearchSourceResult, collect_search_source


PERSON = Person("Иван", "Иванов", "Иванович")


def _quiet(monkeypatch):
    monkeypatch.setattr("sys.stdout", io.StringIO())
    monkeypatch.setattr("sys.stderr", io.StringIO())
    monkeypatch.setattr("sys.stdin", io.StringIO())


@pytest.mark.parametrize("save", [False, True])
def test_passive_defaults_and_artifact_retention(tmp_path, monkeypatch, save):
    _quiet(monkeypatch)
    monkeypatch.chdir(tmp_path)
    site = Mock(side_effect=AssertionError("passive mode must not crawl the site"))
    monkeypatch.setattr(cli, "collect_public_data", site)
    monkeypatch.setattr(cli, "generate", Mock(side_effect=AssertionError("generation was not selected")))
    seen = []

    def search(auto, domains, **kwargs):
        seen.append(auto)
        assert domains == ("example.test",)
        assert auto.search_engines == ("yandex", "google")
        assert auto.pdf_enabled
        assert not auto.url
        page = auto.search_results_dir / "google.html"
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text("ivan@example.test", encoding="utf-8")
        return SearchSourceResult(collection=CollectionResult(
            emails=("ivan@example.test",),
            email_sources=(EmailSourceRecord("ivan@example.test", "search", source_path=str(page)),),
        ))

    monkeypatch.setattr(cli, "collect_search_source", search)
    setka = Mock(return_value=CollectionResult(people=(PERSON,)))
    monkeypatch.setattr(cli, "collect_setka_people", setka)
    args = ["--domain", "@example.test", "--company", "Пример", "-o", "results"]
    assert cli.main(args + (["--save-artifacts"] if save else [])) == 0
    site.assert_not_called()
    setka.assert_called_once()
    assert (tmp_path / "results/emails.txt").read_text() == "ivan@example.test\n"
    assert (tmp_path / "results/fio.txt").read_text() == "Иванов Иван Иванович\n"
    if save:
        assert (tmp_path / "results/evidence.xlsx").is_file()
        assert (tmp_path / "results/collection.log").is_file()
        assert (seen[0].search_results_dir / "google.html").is_file()
    else:
        assert {p.name for p in (tmp_path / "results").iterdir()} == {"emails.txt", "fio.txt"}
        assert not seen[0].search_results_dir.exists()


def test_custom_engine_keeps_default_setka(tmp_path, monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.chdir(tmp_path)
    search = Mock(return_value=SearchSourceResult(collection=CollectionResult()))
    setka = Mock(return_value=CollectionResult())
    monkeypatch.setattr(cli, "collect_search_source", search)
    monkeypatch.setattr(cli, "collect_setka_people", setka)
    assert cli.main(["--domain", "example.test", "--company", "Пример", "-s", "google",
                     "--setka-max-pages", "2"]) == 0
    assert search.call_args.args[0].search_engines == ("google",)
    assert setka.call_args.args[1].setka_max_pages == 2


def test_active_target_file_scopes_and_generated_candidates_order(tmp_path, monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.chdir(tmp_path)
    targets = tmp_path / "targets.txt"
    targets.write_text("\ufeff# test\nhttps://one.test/\nhttp://two.test/team\nhttps://one.test/\n")
    site = Mock(return_value=CollectionResult(
        people=(PERSON,), emails=("support@example.test", "i.ivanov@example.test"),
    ))
    monkeypatch.setattr(cli, "collect_public_data", site)
    monkeypatch.setattr(cli, "collect_search_source", Mock(side_effect=AssertionError("active default must not search")))
    monkeypatch.setattr(cli, "collect_setka_people", Mock(side_effect=AssertionError("active default must not use Setka")))
    assert cli.main(["-u", str(targets), "--domain", "example.test", "-o", "results", "-g",
                     "--person-pattern", "{lastname}.{f}", "--kind", "email", "--no-pattern-prompt",
                     "--katana-depth", "1"]) == 0
    auto = site.call_args.args[0]
    assert auto.site_crawler == "katana"
    assert auto.url == "https://one.test/"
    assert auto.extra_urls == ("http://two.test/team",)
    assert auto.allowed_domains == ("one.test", "two.test")
    assert auto.max_depth == 0
    candidates = (tmp_path / "results/logins.txt").read_text().splitlines()
    assert candidates[:2] == ["support@example.test", "i.ivanov@example.test"]
    assert candidates[2:] == ["ivanov.i@example.test"]
    assert len(candidates) == len(set(candidates))
    assert (tmp_path / "results/emails.txt").read_text().splitlines() == candidates[:2]


def test_invalid_input_fails_before_collection(tmp_path, monkeypatch):
    _quiet(monkeypatch)
    collect = Mock(side_effect=AssertionError("input must be validated first"))
    monkeypatch.setattr(cli, "run_auto_collection", collect)
    with pytest.raises(SystemExit) as error:
        cli.main(["-u", str(tmp_path / "missing.txt")])
    assert error.value.code == 2
    collect.assert_not_called()


def test_active_interrupt_preserves_findings_without_artifacts(tmp_path, monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.chdir(tmp_path)
    def collect(auto, *, on_progress, **kwargs):
        on_progress(CollectionResult(people=(PERSON,), emails=("person@example.test",)))
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "collect_public_data", collect)
    assert cli.main(["-u", "https://example.test", "-o", "results"]) == 130
    assert (tmp_path / "results/fio.txt").read_text().strip() == "Иванов Иван Иванович"
    assert (tmp_path / "results/emails.txt").read_text().strip() == "person@example.test"
    assert len(list((tmp_path / "results").iterdir())) == 2


def _office_bytes(kind):
    text = "Иван Иванов Иванович person@example.test"
    parts = {
        "docx": {"word/document.xml": f'<doc><p><t>{text}</t></p></doc>'},
        "pptx": {"ppt/presentation.xml": "<presentation/>", "ppt/slides/slide1.xml": f'<slide><p><t>{text}</t></p></slide>'},
        "xlsx": {"xl/workbook.xml": "<workbook/>", "xl/sharedStrings.xml": f'<sst><si><t>{text}</t></si></sst>',
                 "xl/worksheets/sheet1.xml": '<sheet><row><c t="s"><v>0</v></c></row></sheet>'},
    }.get(kind, {"content.xml": f'<document><p>{text}</p></document>'})
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        for name, value in parts.items():
            archive.writestr(name, value)
    return output.getvalue()


@pytest.mark.parametrize("kind", ["docx", "pptx", "xlsx", "odt", "odp", "ods", "txt", "csv"])
def test_document_text_and_type(tmp_path, kind):
    data = ("Иван Иванов Иванович person@example.test".encode("cp1251")
            if kind in {"txt", "csv"} else _office_bytes(kind))
    path = tmp_path / ("staff." + kind)
    path.write_bytes(data)
    assert detect_document_type("https://example.test/staff." + kind, data) == kind
    text = extract_document_text(path)
    assert "Иван Иванов Иванович" in text
    assert "person@example.test" in text


def test_active_collects_docx_on_last_page_depth(tmp_path):
    page_url = "https://example.test/"
    doc_url = page_url + "staff.docx"
    fetched = []
    class Fetcher:
        def fetch_text(self, url, **kwargs):
            fetched.append(url)
            assert url == page_url
            return FetchResponse(url, 200, '<a href="staff.docx">staff</a><a href="next">next</a>', "text/html")
        def fetch_bytes(self, url, **kwargs):
            fetched.append(url)
            return FetchBinaryResponse(url, 200, _office_bytes("docx"))
    auto = AutoConfig(url=page_url, browser_crawl=False, max_depth=0, max_pages=1,
                      respect_robots_txt=False, pdf_files_dir=tmp_path / "documents")
    result = collect_public_data(auto, fetcher=Fetcher())
    assert fetched == [page_url, doc_url]
    assert result.people == (PERSON,)
    assert result.emails == ("person@example.test",)
    assert result.person_sources[0].source_type == "docx"


def test_passive_downloads_search_document_without_crawling_company(tmp_path):
    fetched = []
    doc_url = "https://example.test/staff.pptx"
    class Fetcher:
        def fetch_rendered_html(self, url, **kwargs):
            fetched.append(url)
            assert url.startswith("https://yandex.ru/search/")
            return FetchResponse(url, 200, f'<a href="{doc_url}">Staff</a>', "text/html")
        def fetch_bytes(self, url, **kwargs):
            fetched.append(url)
            assert url == doc_url
            return FetchBinaryResponse(url, 200, _office_bytes("pptx"))
    result = collect_search_source(AutoConfig(
        search_fetch_enabled=True, search_dorks=('"@{domain}"',),
        search_results_dir=tmp_path / "search", pdf_files_dir=tmp_path / "docs",
        found_emails_path=None,
    ), ("example.test",), fetcher=Fetcher())
    assert len(fetched) == 2
    assert result.collection.people == (PERSON,)
    assert result.collection.emails == ("person@example.test",)
