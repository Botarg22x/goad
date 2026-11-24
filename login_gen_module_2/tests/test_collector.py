from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from logingen.collector import (
    build_vedomosti_search_url,
    collect_public_data,
    extract_emails,
    extract_people,
    extract_standalone_people,
    extract_vedomosti_people,
    is_allowed_url,
)
from logingen.models import AutoConfig
from logingen.playwright_fetcher import FetchResponse, PlaywrightFetchError


class FakeCollectorFetcher:
    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages
        self.text_urls: list[str] = []
        self.rendered_urls: list[str] = []

    def fetch_text(
        self,
        url: str,
        *,
        timeout_seconds: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResponse:
        self.text_urls.append(url)
        return FetchResponse(
            url=url,
            status_code=200,
            body=self._pages[url],
            content_type="text/html",
        )

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        self.rendered_urls.append(url)
        return self.fetch_text(url)


class JsShellFetcher(FakeCollectorFetcher):
    def __init__(self, pages: dict[str, str], rendered_pages: dict[str, str]) -> None:
        super().__init__(pages)
        self._rendered_pages = rendered_pages

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        self.rendered_urls.append(url)
        return FetchResponse(url=url, status_code=200, body=self._rendered_pages[url], content_type="text/html")


class FailingJsShellFetcher(FakeCollectorFetcher):
    def fetch_rendered_html(self, url: str) -> FetchResponse:
        self.rendered_urls.append(url)
        raise PlaywrightFetchError("browser unavailable")


class RobotsForbiddenFetcher(FakeCollectorFetcher):
    def __init__(self, pages: dict[str, str], *, status_code: int = 403) -> None:
        super().__init__(pages)
        self._status_code = status_code

    def fetch_text(
        self,
        url: str,
        *,
        timeout_seconds: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResponse:
        self.text_urls.append(url)
        if url.endswith("/robots.txt"):
            return FetchResponse(
                url=url,
                status_code=self._status_code,
                body="Forbidden",
                content_type="text/plain",
            )
        return FetchResponse(
            url=url,
            status_code=200,
            body=self._pages[url],
            content_type="text/html",
        )


class CollectorParserTests(unittest.TestCase):
    def test_extracts_public_emails(self) -> None:
        text = "Contacts: info@example.ru, mailto:support@example.ru?subject=test"
        self.assertEqual(extract_emails(text), ("info@example.ru", "support@example.ru"))

    def test_extracts_russian_people(self) -> None:
        people = extract_people("Команда: Иван Иванов Дмитриевич, Анна Смирнова.")
        self.assertEqual(people[0].firstname, "Иван")
        self.assertEqual(people[0].lastname, "Иванов")
        self.assertEqual(people[0].patronymic, "Дмитриевич")
        self.assertEqual(people[1].firstname, "Анна")
        self.assertEqual(people[1].lastname, "Смирнова")

    def test_standalone_lines_accept_uncommon_names_but_not_roles(self) -> None:
        text = (
            "Состав команды\n"
            "Елизавета Севастьянова\n"
            "коммерческий директор\n"
            "Натали Степанцова\n"
            "руководитель управления рекламы и PR\n"
            "Дмитрий Зиканов\n"
            "генеральный директор\n"
        )

        self.assertEqual(
            [(person.firstname, person.lastname) for person in extract_standalone_people(text)],
            [
                ("Елизавета", "Севастьянова"),
                ("Натали", "Степанцова"),
                ("Дмитрий", "Зиканов"),
            ],
        )

    def test_does_not_extract_surname_broken_across_lines(self) -> None:
        self.assertEqual(extract_people("Наталья Подоль-\nская."), ())

    def test_builds_vedomosti_search_url(self) -> None:
        url = build_vedomosti_search_url("мяу")
        self.assertIn("https://events.vedomosti.ru/search?", url)
        self.assertIn("q=%D0%BC%D1%8F%D1%83", url)
        self.assertIn("template=speakers", url)

    def test_extracts_vedomosti_speaker_names(self) -> None:
        html = """
        <div class="b-search-speaker__name">Иван Иванов</div>
        <a class="card b-search-speaker__name">
          <span>Анна Смирнова</span>
        </a>
        """

        people = extract_vedomosti_people(html)

        self.assertEqual(people[0].firstname, "Иван")
        self.assertEqual(people[0].lastname, "Иванов")
        self.assertEqual(people[1].firstname, "Анна")
        self.assertEqual(people[1].lastname, "Смирнова")


class CollectorCrawlerTests(unittest.TestCase):
    def test_static_findings_keep_a_saved_html_source(self) -> None:
        url = "https://example.test/team"
        html = "<html><body>Иван Иванов ivan@example.test</body></html>"
        with tempfile.TemporaryDirectory() as directory:
            result = collect_public_data(
                AutoConfig(url=url, max_pages=1, browser_crawl=False,
                           respect_robots_txt=False, browser_pages_dir=Path(directory)),
                fetcher=FakeCollectorFetcher({url: html}),
            )
            self.assertTrue(result.person_sources)
            self.assertTrue(result.email_sources)
            self.assertEqual(Path(result.person_sources[0].source_path).read_text(encoding="utf-8"), html)
            self.assertEqual(result.email_sources[0].source_path, result.person_sources[0].source_path)

    def test_exact_hosts_do_not_implicitly_include_subdomains(self) -> None:
        self.assertTrue(is_allowed_url(
            "https://example.test/", ("example.test",), exact_hosts=True,
        ))
        self.assertFalse(is_allowed_url(
            "https://app.example.test/", ("example.test",), exact_hosts=True,
        ))
        self.assertTrue(is_allowed_url(
            "https://app.example.test/", ("example.test", "app.example.test"),
            exact_hosts=True,
        ))

    def test_js_shell_falls_back_to_browser_but_static_data_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            dynamic_url = "https://example.test/"
            static_url = "https://example.test/contacts"
            fetcher = JsShellFetcher(
                {
                    dynamic_url: '<html><div id="root"></div><script src="/app.js"></script></html>',
                    static_url: '<html><div id="root">info@example.test</div><script src="/app.js"></script></html>',
                },
                {dynamic_url: "<html><body>Анна Смирнова support@example.test</body></html>"},
            )
            config = AutoConfig(
                url=dynamic_url, extra_urls=(static_url,), max_pages=2, max_depth=0,
                browser_crawl=False, respect_robots_txt=False,
                browser_pages_dir=Path(temp_dir),
            )
            result = collect_public_data(config, fetcher=fetcher)

        self.assertEqual(fetcher.rendered_urls, [dynamic_url])
        self.assertIn("support@example.test", result.emails)
        self.assertIn("info@example.test", result.emails)
        self.assertTrue(any(person.firstname == "Анна" for person in result.people))

    def test_plain_static_page_does_not_launch_browser(self) -> None:
        url = "https://example.test/"
        fetcher = FakeCollectorFetcher({url: "<html><body>Company profile</body></html>"})
        result = collect_public_data(
            AutoConfig(url=url, max_pages=1, browser_crawl=False, respect_robots_txt=False),
            fetcher=fetcher,
        )
        self.assertEqual(result.visited_urls, (url,))
        self.assertEqual(fetcher.rendered_urls, [])

    def test_failed_js_fallback_keeps_static_links_and_continues(self) -> None:
        url = "https://example.test/"
        contact_url = "https://example.test/contacts"
        fetcher = FailingJsShellFetcher({
            url: '<html><div id="root"></div><a href="/contacts">Contacts</a><script src="/app.js"></script></html>',
            contact_url: "<html><body>info@example.test</body></html>",
        })
        result = collect_public_data(
            AutoConfig(url=url, max_pages=2, max_depth=1, browser_crawl=False,
                       respect_robots_txt=False),
            fetcher=fetcher,
        )
        self.assertEqual(fetcher.rendered_urls, [url])
        self.assertIn("info@example.test", result.emails)
        self.assertTrue(any("Browser fallback failed" in warning for warning in result.warnings))

    def test_disabled_documents_are_skipped_while_html_is_collected(self) -> None:
        base = "https://example.test/"
        fetcher = FakeCollectorFetcher({
            base: '<a href="staff.PDF?v=1">PDF</a><a href="staff.pptx">Slides</a>'
                  '<a href="contacts">Contacts</a>',
            base + "contacts": "info@example.test",
        })
        result = collect_public_data(
            AutoConfig(url=base, pdf_enabled=False, browser_crawl=False, respect_robots_txt=False),
            fetcher=fetcher,
        )

        self.assertEqual(fetcher.text_urls, [base, base + "contacts"])
        self.assertEqual(result.emails, ("info@example.test",))
        self.assertIn(base + "staff.PDF?v=1", result.skipped_urls)
        self.assertIn(base + "staff.pptx", result.skipped_urls)

    def test_crawls_in_scope_pages(self) -> None:
        index_url = "http://example.test/index.html"
        team_url = "http://example.test/team.html"
        fetcher = FakeCollectorFetcher(
            {
                index_url: """
                <html>
                  <body>
                    Иван Иванов Дмитриевич
                    <a href="/team.html">team</a>
                    <a href="mailto:press@example.ru">press</a>
                  </body>
                </html>
                """,
                team_url: "<html><body>Анна Смирнова support@example.ru</body></html>",
            }
        )
        config = AutoConfig(
            enabled=True,
            url=index_url,
            max_pages=5,
            max_depth=1,
            log_path=None,
            respect_robots_txt=False,
            browser_crawl=False,
        )
        result = collect_public_data(config, fetcher=fetcher)

        self.assertEqual(len(result.visited_urls), 2)
        self.assertIn("press@example.ru", result.emails)
        self.assertIn("support@example.ru", result.emails)
        self.assertEqual(result.domains, ("example.ru",))
        self.assertEqual(len(result.people), 2)

    def test_browser_crawl_is_default_for_company_site_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            index_url = "http://example.test/index.html"
            fetcher = FakeCollectorFetcher(
                {
                    index_url: "<html><body>support@example.ru</body></html>",
                }
            )
            config = AutoConfig(
                enabled=True,
                url=index_url,
                max_pages=1,
                log_path=None,
                respect_robots_txt=False,
                browser_pages_dir=Path(temp_dir),
            )

            result = collect_public_data(config, fetcher=fetcher)

        self.assertEqual(result.visited_urls, (index_url,))
        self.assertEqual(fetcher.rendered_urls, [index_url])

    def test_robots_401_and_403_do_not_block_browser_crawl(self) -> None:
        for status_code in (401, 403):
            with self.subTest(status_code=status_code), tempfile.TemporaryDirectory() as temp_dir:
                index_url = "http://example.test/index.html"
                fetcher = RobotsForbiddenFetcher(
                    {
                        index_url: "<html><body>support@example.ru</body></html>",
                    },
                    status_code=status_code,
                )
                config = AutoConfig(
                    enabled=True,
                    url=index_url,
                    max_pages=1,
                    log_path=None,
                    browser_crawl=True,
                    browser_pages_dir=Path(temp_dir),
                )

                result = collect_public_data(config, fetcher=fetcher)

            self.assertEqual(result.visited_urls, (index_url,))
            self.assertEqual(result.emails, ("support@example.ru",))
            self.assertEqual(fetcher.rendered_urls, [index_url])


if __name__ == "__main__":
    unittest.main()
