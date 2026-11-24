from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import logingen.search_sources as search_sources_module
from logingen.models import AutoConfig
from logingen.playwright_fetcher import FetchBinaryResponse, FetchResponse
from logingen.search_sources import (
    PdfSourceCandidate,
    SearchQuery,
    SearchResultEmail,
    build_google_search_url,
    build_search_queries,
    collect_search_source,
    collect_pdf_sources,
    extract_pdf_people,
    extract_loose_emails,
    fetch_search_pages,
    fetch_pdf_files,
    is_google_captcha_html,
    is_yandex_captcha_html,
    parse_search_result_links,
    parse_search_result_email_findings,
    parse_yandex_result_emails,
)


class FakeSearchFetcher:
    def __init__(self, pages: dict[str, str], binary_pages: dict[str, bytes] | None = None) -> None:
        self._pages = pages
        self._binary_pages = binary_pages or {}

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        return FetchResponse(
            url=url,
            status_code=200,
            body=self._pages[url],
            content_type="text/html",
        )

    def fetch_bytes(self, url: str, *, timeout_seconds=None, headers=None) -> FetchBinaryResponse:
        return FetchBinaryResponse(
            url=url,
            status_code=200,
            body=self._binary_pages[url],
            content_type="application/pdf",
        )


class FakeManualCaptchaFetcher(FakeSearchFetcher):
    def fetch_rendered_html_with_manual_captcha(self, url, captcha_detector) -> FetchResponse:
        return self.fetch_rendered_html(url)


class FakeManualSessionFetcher(FakeSearchFetcher):
    def __init__(self, pages: dict[str, str]) -> None:
        super().__init__(pages)
        self.session_urls: list[str] = []

    def fetch_rendered_html_in_manual_session(self, url, captcha_detector) -> FetchResponse:
        self.session_urls.append(url)
        return self.fetch_rendered_html(url)


class SearchSourceTests(unittest.TestCase):
    def test_reports_pdf_emails_before_next_download_is_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_url = "https://company.ru/first.pdf"
            second_url = "https://company.ru/second.pdf"

            class InterruptingFetcher(FakeSearchFetcher):
                def fetch_bytes(self, url: str, *, timeout_seconds=None, headers=None) -> FetchBinaryResponse:
                    if url == second_url:
                        raise KeyboardInterrupt
                    return super().fetch_bytes(url, timeout_seconds=timeout_seconds, headers=headers)

            candidates = tuple(
                PdfSourceCandidate(
                    url=url, engine="yandex", query="company",
                    query_url="https://yandex.ru/search/", source_path=root / "search.html",
                )
                for url in (first_url, second_url)
            )
            snapshots = []
            with mock.patch.object(search_sources_module, "extract_pdf_text", return_value="info@company.ru"):
                with self.assertRaises(KeyboardInterrupt):
                    collect_pdf_sources(
                        candidates,
                        AutoConfig(pdf_files_dir=root / "pdf"),
                        fetcher=InterruptingFetcher({}, {first_url: b"%PDF-1.4\n"}),
                        on_progress=snapshots.append,
                    )
            self.assertEqual(snapshots[-1].emails, ("info@company.ru",))
            self.assertTrue(snapshots[-1].email_sources[0].source_path)

    def test_reports_search_emails_before_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dorks = ('site:{domain} "contacts"', 'site:{domain} "team"')
            queries = build_search_queries(("company.ru",), dorks=dorks)

            class InterruptingFetcher(FakeSearchFetcher):
                def fetch_rendered_html(self, url: str) -> FetchResponse:
                    if url == queries[1].url:
                        raise KeyboardInterrupt
                    return super().fetch_rendered_html(url)

            snapshots = []
            config = AutoConfig(
                search_enabled=True,
                search_fetch_enabled=True,
                search_dorks=dorks,
                search_results_dir=root / "search",
                pdf_enabled=False,
            )
            with self.assertRaises(KeyboardInterrupt):
                collect_search_source(
                    config, ("company.ru",),
                    fetcher=InterruptingFetcher({
                        queries[0].url: '<div class="OrganicTextContentSpan">info@company.ru</div>',
                    }),
                    on_progress=snapshots.append,
                )
            self.assertEqual(snapshots[-1].emails, ("info@company.ru",))
            self.assertTrue(snapshots[-1].email_sources[0].source_path)

    def test_no_documents_cli_keeps_search_emails_without_downloading_pdf(self) -> None:
        from dataclasses import replace
        from logingen.cli import apply_overrides, build_parser, cli_default_config

        args = build_parser().parse_args(["-s", "yandex", "--no-documents"])
        auto = apply_overrides(cli_default_config(), args).auto
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dorks = ('filetype:pdf "@{domain}"',)
            query_url = build_search_queries(("company.ru",), dorks=dorks)[0].url
            auto = replace(
                auto, search_dorks=dorks, search_results_dir=root / "search",
                pdf_files_dir=root / "pdf", found_emails_path=None,
            )
            result = collect_search_source(
                auto, ("company.ru",),
                fetcher=FakeSearchFetcher({query_url: (
                    '<a href="https://company.ru/contacts.pdf">Contacts</a>'
                    '<div class="OrganicTextContentSpan">E-mail: info@company.ru</div>'
                )}),
            )

            self.assertEqual(result.collection.emails, ("info@company.ru",))
            self.assertEqual(result.pdfs, ())
            self.assertFalse(auto.pdf_files_dir.exists())

    def test_pdf_extracts_names_from_every_page(self) -> None:
        text = (
            "Команда года\f"
            "Состав команды\n"
            "Елизавета Севастьянова\nкоммерческий директор\n"
            "Елизавета Гудзь\nруководитель управления\n"
            "Натали Степанцова\nруководитель рекламы\n"
            "Дмитрий Зиканов\nгенеральный директор\f"
            "Звездные жильцы\nВладимир Пресняков и Наталья Подольская.\n"
        )

        self.assertEqual(
            [(person.firstname, person.lastname) for person in extract_pdf_people(text)],
            [
                ("Елизавета", "Севастьянова"),
                ("Елизавета", "Гудзь"),
                ("Натали", "Степанцова"),
                ("Дмитрий", "Зиканов"),
                ("Владимир", "Пресняков"),
                ("Наталья", "Подольская"),
            ],
        )

    def test_pdf_candidates_are_deduplicated_by_url_before_limit(self) -> None:
        class CountingFetcher(FakeSearchFetcher):
            def __init__(self, binary_pages):
                super().__init__({}, binary_pages)
                self.requested: list[str] = []

            def fetch_bytes(self, url, *, timeout_seconds=None, headers=None):
                self.requested.append(url)
                return super().fetch_bytes(url, timeout_seconds=timeout_seconds, headers=headers)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first_url = "https://example.test/first.pdf"
            second_url = "https://example.test/second.pdf"
            candidates = (
                PdfSourceCandidate(first_url, "yandex", "query 1", "https://yandex.test/1", root),
                PdfSourceCandidate(first_url, "yandex", "query 2", "https://yandex.test/2", root),
                PdfSourceCandidate(second_url, "yandex", "query 3", "https://yandex.test/3", root),
            )
            fetcher = CountingFetcher({first_url: b"%PDF-1.7 first", second_url: b"%PDF-1.7 second"})
            with mock.patch.object(search_sources_module, "extract_pdf_text", return_value=""):
                fetched, result = collect_pdf_sources(
                    candidates,
                    AutoConfig(pdf_files_dir=root / "pdf", pdf_max_files=2),
                    fetcher=fetcher,
                )

            self.assertEqual(fetcher.requested, [first_url, second_url])
            self.assertEqual(len(fetched), 2)
            self.assertEqual(fetched[0].source.query, "query 1")
            self.assertEqual(result.warnings, ())

    def test_pdf_people_keep_document_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            url = "https://example.test/team.pdf"
            candidate = PdfSourceCandidate(url, "yandex", "team", "https://yandex.test/search", root)
            fetcher = FakeSearchFetcher({}, {url: b"%PDF-1.7 fake"})
            with mock.patch.object(search_sources_module, "extract_pdf_text", return_value="Иван Иванов"):
                _, result = collect_pdf_sources(
                    (candidate,), AutoConfig(pdf_files_dir=root / "pdf"), fetcher=fetcher,
                )
            self.assertTrue(result.person_sources)
            self.assertEqual(result.person_sources[0].url, url)
            self.assertTrue(Path(result.person_sources[0].source_path).is_file())

    def test_pdf_download_records_hostname_mismatch_warning(self) -> None:
        class MismatchedCertificateFetcher:
            def fetch_bytes(self, url, *, timeout_seconds=None, headers=None):
                return FetchBinaryResponse(
                    url=url,
                    status_code=200,
                    body=b"%PDF-1.7 fake",
                    content_type="application/pdf",
                    tls_warning=f"PDF: сертификат не соответствует домену; повторный запрос без проверки TLS: {url}",
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            url = "https://example.test/contacts.pdf"
            candidate = PdfSourceCandidate(url, "yandex", "query", "https://yandex.test", root)
            fetched, warnings = fetch_pdf_files(
                (candidate,),
                AutoConfig(pdf_files_dir=root / "pdf"),
                fetcher=MismatchedCertificateFetcher(),
            )

            self.assertEqual(len(fetched), 1)
            self.assertEqual(fetched[0].path.read_bytes(), b"%PDF-1.7 fake")
            self.assertEqual(
                warnings,
                (f"PDF: сертификат не соответствует домену; повторный запрос без проверки TLS: {url}",),
            )

    def test_default_dorks_use_petr_and_preserve_ru_domain(self) -> None:
        queries = build_search_queries(("muc-nsk.ru",))
        rendered = tuple(query.query for query in queries)

        self.assertIn('"petr@muc-nsk.ru"', rendered)
        self.assertFalse(any("petp@" in query for query in rendered))
        self.assertTrue(all(query.domain == "muc-nsk.ru" for query in queries))

    def test_builds_exact_yandex_queries_from_dorks(self) -> None:
        queries = build_search_queries(
            ("company.ru",),
            dorks=('"ivanov@{domain}"', '"a@{domain}"'),
        )

        self.assertEqual(queries[0].query, '"ivanov@company.ru"')
        self.assertIn("text=%22ivanov%40company.ru%22", queries[0].url)
        self.assertEqual(queries[1].query, '"a@company.ru"')

    def test_builds_google_queries_from_common_dorks(self) -> None:
        queries = build_search_queries(
            ("www.company.ru",),
            dorks=('site:{domain} "{company}" "ivanov@{email_domain}"',),
            engines=("google",),
        )

        self.assertEqual(queries[0].engine, "google")
        self.assertEqual(queries[0].query, 'site:www.company.ru "company" "ivanov@www.company.ru"')
        self.assertEqual(queries[0].url, build_google_search_url(queries[0].query))

    def test_extracts_emails_split_by_html_tags(self) -> None:
        html = "found <b>ivanov</b><span>@</span><i>company</i><em>.</em>ru"

        self.assertEqual(extract_loose_emails(html), ("ivanov@company.ru",))

    def test_strips_file_extension_after_email_in_search_result(self) -> None:
        html = "document href kadyrova_a_a@magnit.ru.pdf"

        self.assertEqual(extract_loose_emails(html), ("kadyrova_a_a@magnit.ru",))

    def test_parses_yandex_snippet_classes(self) -> None:
        html = """
        <html>
          <body>
            <div class="organic__text">
              Contacts: <b>petrov</b> @ <span>company</span> . ru
            </div>
          </body>
        </html>
        """

        self.assertEqual(parse_yandex_result_emails(html), ("petrov@company.ru",))

    def test_parses_yandex_highlighted_local_prefix_split_by_tags(self) -> None:
        html = """
        <span role="text" class="OrganicTextContentSpan">
          "Хлебобулочные изделия" - pa.
          <b>ivanov</b>
          "@"
          <b>auchan</b>
          "."
          <b>ru</b>
        </span>
        """

        self.assertEqual(parse_yandex_result_emails(html), ("pa.ivanov@auchan.ru",))

    def test_parses_search_email_source_url_from_result_link(self) -> None:
        html = """
        <a href="https://example.org/org/67">Organization</a>
        <span role="text" class="OrganicTextContentSpan">
          Contacts: zubkova_e_<b>a</b>@<b>magnit</b>.<b>ru</b>
        </span>
        """

        findings = parse_search_result_email_findings(html, engine="yandex")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].email, "zubkova_e_a@magnit.ru")
        self.assertEqual(findings[0].found_url, "https://example.org/org/67")

    def test_unwraps_google_result_redirect_url_for_email_source(self) -> None:
        html = """
        <a href="/url?q=https%3A%2F%2Fcompany.ru%2Fcontacts%3Fid%3D1&sa=U">Contacts</a>
        <div class="text-container__text">mail: info @ company . ru</div>
        """

        findings = parse_search_result_email_findings(html, engine="google")

        self.assertEqual(findings[0].email, "info@company.ru")
        self.assertEqual(findings[0].found_url, "https://company.ru/contacts?id=1")

    def test_google_structured_result_comment_links_email_to_source(self) -> None:
        html = """
        <div>mail: info@company.ru</div>
        <!--TgQPHd|||[&quot;mail: info@company.ru&quot;,
             &quot;https://encrypted-tbn2.gstatic.com/faviconV2&quot;,
             &quot;https://company.ru/contacts&quot;]-->
        """

        findings = parse_search_result_email_findings(html, engine="google")

        self.assertEqual(findings, (SearchResultEmail(
            email="info@company.ru", found_url="https://company.ru/contacts"
        ),))

    def test_google_comment_does_not_guess_between_multiple_sources(self) -> None:
        html = """
        <div>mail: info@company.ru</div>
        <!--TgQPHd|||[&quot;mail: info@company.ru&quot;,
             &quot;https://company.ru/contact&quot;,
             &quot;https://other.example/contact&quot;]-->
        """

        findings = parse_search_result_email_findings(html, engine="google")

        self.assertEqual(findings, (SearchResultEmail(email="info@company.ru"),))

    def test_google_comment_enriches_visible_email_only_and_decodes_url(self) -> None:
        html = r'''
        <div>mail: info@company.ru</div>
        <!--TgQPHd|||[&quot;mail: info@company.ru and hidden@company.ru&quot;,
             &quot;https://company.ru/contacts?page\u003d2&quot;]-->
        '''

        findings = parse_search_result_email_findings(html, engine="google")

        self.assertEqual(findings, (SearchResultEmail(
            email="info@company.ru", found_url="https://company.ru/contacts?page=2"
        ),))

    def test_parses_search_result_links_for_pdf_sources(self) -> None:
        html = """
        <a href="https://example.org/docs/order.pdf">Order PDF</a>
        <div class="OrganicTextContentSpan">document</div>
        """

        self.assertEqual(parse_search_result_links(html), ("https://example.org/docs/order.pdf",))

    def test_google_search_page_with_recaptcha_script_is_not_captcha(self) -> None:
        html = '<html><title>"ivanov@company.ru" - Google Search</title><script src="/recaptcha/api.js"></script></html>'

        self.assertFalse(is_google_captcha_html(html))

    def test_collect_source_fetches_and_parses_yandex_html(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            found_path = root / "found.txt"
            dorks = ('"elena@{domain}"',)
            query_url = build_search_queries(("company.ru",), dorks=dorks)[0].url
            config = AutoConfig(
                search_dorks=dorks,
                search_results_dir=root / "saved",
                found_emails_path=found_path,
                search_fetch_enabled=True,
            )

            result = collect_search_source(
                config,
                ("company.ru",),
                fetcher=FakeSearchFetcher(
                    {
                        query_url: (
                            '<a href="https://example.org/contacts">Contacts</a>'
                            '<div class="serp-item__text">manager <b>elena</b>@company.ru and info@company.ru</div>'
                        ),
                    }
                ),
            )

            self.assertEqual(result.collection.emails, ("info@company.ru",))
            self.assertEqual(found_path.read_text(encoding="utf-8").strip().splitlines(), ["info@company.ru"])
            self.assertEqual((found_path.parent / "mail_from_yandex.txt").read_text(encoding="utf-8").strip(), "info@company.ru")
            self.assertEqual(result.collection.email_sources[0].query, '"elena@company.ru"')
            self.assertEqual(result.collection.email_sources[0].url, "https://example.org/contacts")
            self.assertEqual(result.collection.email_sources[0].query_url, query_url)
            self.assertEqual(len(result.fetched), 1)
            self.assertTrue(result.fetched[0].path.exists())

    def test_collect_source_keeps_google_result_link_with_saved_page(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            dorks = ('"admin@{domain}"',)
            query_url = build_search_queries(
                ("company.ru",), dorks=dorks, engines=("google",)
            )[0].url
            config = AutoConfig(
                search_dorks=dorks,
                search_engines=("google",),
                search_results_dir=root / "saved",
                found_emails_path=root / "found.txt",
                search_fetch_enabled=True,
            )
            html = """
                <div>info@company.ru</div>
                <!--TgQPHd|||[&quot;info@company.ru&quot;,
                     &quot;https://company.ru/contacts&quot;]-->
            """

            result = collect_search_source(
                config, ("company.ru",),
                fetcher=FakeSearchFetcher({query_url: html}),
            )

            self.assertEqual(result.collection.emails, ("info@company.ru",))
            source = result.collection.email_sources[0]
            self.assertEqual(source.found_url, "https://company.ru/contacts")
            self.assertEqual(source.query_url, query_url)
            self.assertTrue(Path(source.source_path).is_file())

    def test_collect_source_excludes_emails_used_as_search_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            found_path = root / "found.txt"
            dorks = ('"ivanov@{domain}"',)
            query_url = build_search_queries(("company.ru",), dorks=dorks)[0].url
            config = AutoConfig(
                search_dorks=dorks,
                search_results_dir=root / "saved",
                found_emails_path=found_path,
                search_fetch_enabled=True,
            )

            result = collect_search_source(
                config,
                ("company.ru",),
                fetcher=FakeSearchFetcher(
                    {
                        query_url: '<span class="OrganicTextContentSpan">ivanov@company.ru and pa.<b>ivanov</b>@company.ru</span>',
                    }
                ),
            )

            self.assertEqual(result.collection.emails, ("pa.ivanov@company.ru",))
            self.assertEqual(found_path.read_text(encoding="utf-8").strip(), "pa.ivanov@company.ru")

    def test_collect_source_fetches_and_parses_pdf_results(self) -> None:
        original_extract_pdf_text = search_sources_module.extract_pdf_text
        search_sources_module.extract_pdf_text = lambda _path: "PDF contact: zakup @ company . ru"
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                found_path = root / "found.txt"
                dorks = ('filetype:pdf "@{domain}"',)
                query_url = build_search_queries(("company.ru",), dorks=dorks)[0].url
                pdf_url = "https://example.org/docs/company.pdf"
                config = AutoConfig(
                    search_dorks=dorks,
                    search_results_dir=root / "saved",
                    found_emails_path=found_path,
                    search_fetch_enabled=True,
                    pdf_files_dir=root / "pdf",
                )

                result = collect_search_source(
                    config,
                    ("company.ru",),
                    fetcher=FakeSearchFetcher(
                        {query_url: f'<a href="{pdf_url}">PDF</a><div class="OrganicTextContentSpan">document</div>'},
                        {pdf_url: b"%PDF-1.7 fake"},
                    ),
                )
                self.assertTrue(result.pdfs[0].path.exists())
                self.assertEqual(found_path.read_text(encoding="utf-8").strip(), "zakup@company.ru")
                self.assertEqual(
                    (found_path.parent / "mail_from_pdf.txt").read_text(encoding="utf-8").strip(),
                    "zakup@company.ru",
                )
        finally:
            search_sources_module.extract_pdf_text = original_extract_pdf_text

        self.assertEqual(result.collection.emails, ("zakup@company.ru",))
        self.assertEqual(result.collection.email_sources[0].source_type, "pdf")
        self.assertEqual(result.collection.email_sources[0].url, pdf_url)

    def test_fetches_search_page_html_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "results"
            url = "https://search.local/search.html"
            query = SearchQuery(
                term="ivanov",
                domain="company.ru",
                query='"ivanov@company.ru"',
                url=url,
            )
            config = AutoConfig(
                search_results_dir=output_root,
                search_fetch_enabled=True,
            )

            fetched, warnings = fetch_search_pages(
                (query,),
                config,
                fetcher=FakeSearchFetcher({url: "<html><body>saved result</body></html>"}),
            )

            self.assertEqual(warnings, ())
            self.assertEqual(len(fetched), 1)
            self.assertIn("saved result", fetched[0].path.read_text(encoding="utf-8"))

    def test_fetch_stops_when_yandex_captcha_is_saved(self) -> None:
        captcha_html = '<html><title>Вы не робот?</title><div class="CheckboxCaptcha"></div></html>'
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "results"
            captcha_url = "https://search.local/captcha.html"
            next_url = "https://search.local/next.html"
            queries = (
                SearchQuery(
                    term="ivanov",
                    domain="company.ru",
                    query='"ivanov@company.ru"',
                    url=captcha_url,
                ),
                SearchQuery(
                    term="petrov",
                    domain="company.ru",
                    query='"petrov@company.ru"',
                    url=next_url,
                ),
            )
            config = AutoConfig(
                search_results_dir=output_root,
                search_fetch_enabled=True,
            )

            fetched, warnings = fetch_search_pages(
                queries,
                config,
                fetcher=FakeSearchFetcher(
                    {
                        captcha_url: captcha_html,
                        next_url: "<html>next page</html>",
                    }
                ),
            )

            self.assertEqual(len(fetched), 1)
            self.assertTrue(fetched[0].captcha_detected)
            self.assertTrue(is_yandex_captcha_html(fetched[0].path.read_text(encoding="utf-8")))
            self.assertIn("Yandex: вместо результатов получена CAPTCHA", warnings[0])

    def test_fetch_stops_engine_after_http_429(self) -> None:
        class RateLimitedFetcher(FakeSearchFetcher):
            def __init__(self) -> None:
                super().__init__({})
                self.urls: list[str] = []

            def fetch_rendered_html(self, url: str) -> FetchResponse:
                self.urls.append(url)
                return FetchResponse(
                    url=url,
                    status_code=429,
                    body="<html>too many requests</html>",
                    content_type="text/html",
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            first_url = "https://search.local/limited.html"
            next_url = "https://search.local/must-not-run.html"
            queries = tuple(
                SearchQuery(
                    term=term,
                    domain="company.ru",
                    query=f'"{term}@company.ru"',
                    url=url,
                )
                for term, url in (("ivanov", first_url), ("petrov", next_url))
            )
            config = AutoConfig(
                search_results_dir=Path(temp_dir) / "results",
                search_fetch_enabled=True,
            )
            fetcher = RateLimitedFetcher()

            fetched, warnings = fetch_search_pages(queries, config, fetcher=fetcher)

            self.assertEqual(fetcher.urls, [first_url])
            self.assertEqual(len(fetched), 1)
            self.assertIn("HTTP 429", warnings[0])

    def test_google_captcha_does_not_stop_yandex_fetches(self) -> None:
        google_captcha_html = "<html><body>Our systems have detected unusual traffic from your computer network.</body></html>"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "results"
            google_url = "https://google.local/captcha.html"
            yandex_url = "https://yandex.local/result.html"
            queries = (
                SearchQuery(
                    term="ivanov",
                    domain="company.ru",
                    query='"ivanov@company.ru"',
                    url=google_url,
                    engine="google",
                ),
                SearchQuery(
                    term="ivanov",
                    domain="company.ru",
                    query='"ivanov@company.ru"',
                    url=yandex_url,
                    engine="yandex",
                ),
            )
            config = AutoConfig(
                search_results_dir=output_root,
                search_fetch_enabled=True,
            )

            fetched, warnings = fetch_search_pages(
                queries,
                config,
                fetcher=FakeSearchFetcher(
                    {
                        google_url: google_captcha_html,
                        yandex_url: "<html>yandex result</html>",
                    }
                ),
            )

            self.assertEqual(len(fetched), 2)
            self.assertTrue(fetched[0].captcha_detected)
            self.assertFalse(fetched[1].captcha_detected)
            self.assertIn("Google: вместо результатов получена CAPTCHA", warnings[0])

    def test_fetch_continues_after_manual_captcha_solution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "results"
            first_url = "https://search.local/captcha-solved.html"
            next_url = "https://search.local/next.html"
            queries = (
                SearchQuery(
                    term="ivanov",
                    domain="company.ru",
                    query='"ivanov@company.ru"',
                    url=first_url,
                ),
                SearchQuery(
                    term="petrov",
                    domain="company.ru",
                    query='"petrov@company.ru"',
                    url=next_url,
                ),
            )
            config = AutoConfig(
                search_results_dir=output_root,
                search_fetch_enabled=True,
            )

            fetched, warnings = fetch_search_pages(
                queries,
                config,
                fetcher=FakeManualCaptchaFetcher(
                    {
                        first_url: "<html>solved result</html>",
                        next_url: "<html>next page</html>",
                    }
                ),
            )

            self.assertEqual(warnings, ())
            self.assertEqual(len(fetched), 2)
            self.assertFalse(fetched[0].captcha_detected)

    def test_fetch_uses_single_manual_session_method_for_yandex_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "results"
            first_url = "https://search.local/first.html"
            next_url = "https://search.local/next.html"
            queries = (
                SearchQuery(
                    term="ivanov",
                    domain="company.ru",
                    query='"ivanov@company.ru"',
                    url=first_url,
                ),
                SearchQuery(
                    term="petrov",
                    domain="company.ru",
                    query='"petrov@company.ru"',
                    url=next_url,
                ),
            )
            config = AutoConfig(
                search_results_dir=output_root,
                search_fetch_enabled=True,
            )
            fetcher = FakeManualSessionFetcher(
                {
                    first_url: "<html>first result</html>",
                    next_url: "<html>next result</html>",
                }
            )

            fetched, warnings = fetch_search_pages(queries, config, fetcher=fetcher)

            self.assertEqual(warnings, ())
            self.assertEqual(len(fetched), 2)
            self.assertEqual(fetcher.session_urls, [first_url, next_url])


if __name__ == "__main__":
    unittest.main()
