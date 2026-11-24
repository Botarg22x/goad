from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from logingen.models import AutoConfig
from logingen.playwright_fetcher import FetchResponse
from logingen.search_sources import build_search_url
from logingen.setka import (
    build_setka_members_url,
    build_setka_search_queries,
    build_setka_search_query,
    collect_setka_people,
    extract_setka_company_identity,
    extract_setka_network_ids,
    extract_setka_network_load_more_urls,
    extract_setka_people,
    is_setka_company_networks_url,
    setka_company_page_matches,
)


IVAN_IVANOV = "\u0418\u0432\u0430\u043d \u0418\u0432\u0430\u043d\u043e\u0432"
ANNA_SMIRNOVA = "\u0410\u043d\u043d\u0430 \u0421\u043c\u0438\u0440\u043d\u043e\u0432\u0430"
PETR_PETROV = "\u041f\u0435\u0442\u0440 \u041f\u0435\u0442\u0440\u043e\u0432"
YANA_KIZNER = "\u042f\u043d\u0430 \u041a\u0438\u0437\u043d\u0435\u0440"
PAVEL_EPHIMOV = "Pavel Ephimov"


class FakeSetkaFetcher:
    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages
        self.rendered_urls: list[str] = []

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        self.rendered_urls.append(url)
        return FetchResponse(
            url=url,
            status_code=200,
            body=self._pages[url],
            content_type="text/html",
        )

    def close(self) -> None:
        pass


class SetkaSourceTests(unittest.TestCase):
    def test_reports_collected_people_before_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            search_url = build_setka_search_queries("dns")[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            first_url = build_setka_members_url("first")
            second_url = build_setka_members_url("second")

            class InterruptingFetcher(FakeSetkaFetcher):
                def fetch_rendered_html(self, url: str) -> FetchResponse:
                    if url == second_url:
                        raise KeyboardInterrupt
                    return super().fetch_rendered_html(url)

            fetcher = InterruptingFetcher({
                search_url: f'<a href="{networks_url}">DNS</a>',
                networks_url: (
                    '<title>Сетки компании DNS</title>'
                    '<a href="/networks/first">first</a>'
                    '<a href="/networks/second">second</a>'
                ),
                first_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
            })
            snapshots = []
            with self.assertRaises(KeyboardInterrupt):
                collect_setka_people(
                    "dns",
                    AutoConfig(
                        search_results_dir=root / "search",
                        browser_pages_dir=root / "pages",
                    ),
                    fetcher=fetcher,
                    on_progress=snapshots.append,
                )
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(len(snapshots[0].people), 1)
            self.assertEqual(snapshots[0].person_sources[0].url, first_url)

    def test_uses_at_least_fifteen_seconds_between_setka_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            search_url = build_setka_search_queries("dns", ("yandex",))[0].url
            fake = FakeSetkaFetcher({search_url: "no company page"})
            with patch("logingen.setka.PlaywrightFetchTransport", return_value=fake) as transport:
                collect_setka_people(
                    "dns",
                    AutoConfig(
                        request_delay_seconds=3,
                        search_results_dir=root / "search_results",
                        browser_pages_dir=root / "site_pages",
                    ),
                )
            self.assertEqual(transport.call_args.args[0].request_delay_seconds, 15)

    def test_stops_after_first_429_and_keeps_collected_people(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            search_url = build_setka_search_queries("dns", ("yandex",))[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            first_url = "https://setka.ru/networks/first/members"
            blocked_url = "https://setka.ru/networks/blocked/members"
            never_url = "https://setka.ru/networks/never/members"

            class LimitedFetcher(FakeSetkaFetcher):
                def fetch_rendered_html(self, url: str) -> FetchResponse:
                    if url == blocked_url:
                        self.rendered_urls.append(url)
                        return FetchResponse(url=url, status_code=429, body="", content_type="text/html")
                    return super().fetch_rendered_html(url)

            fetcher = LimitedFetcher({
                search_url: f'<a href="{networks_url}">DNS networks</a>',
                networks_url: (
                    '<title>Сетки компании DNS</title>'
                    '<a href="/networks/first">first</a>'
                    '<a href="/networks/blocked">blocked</a>'
                    '<a href="/networks/never">never</a>'
                ),
                first_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
            })
            events: list[str] = []
            result = collect_setka_people(
                "dns",
                AutoConfig(
                    search_results_dir=root / "search_results",
                    browser_pages_dir=root / "site_pages",
                ),
                log=events.append,
                fetcher=fetcher,
            )

        self.assertEqual(len(result.people), 1)
        self.assertEqual(fetcher.rendered_urls, [search_url, networks_url, first_url, blocked_url])
        self.assertNotIn(never_url, fetcher.rendered_urls)
        self.assertEqual(result.skipped_urls, (blocked_url,))
        self.assertEqual(len([warning for warning in result.warnings if "HTTP 429" in warning]), 1)
        self.assertTrue(any(event.startswith("setka rate limited:") for event in events))
        self.assertTrue(any(f"setka company groups page: url={networks_url}" == event for event in events))
        self.assertTrue(any(f"setka networks parsed: url={networks_url}" in event for event in events))

    def test_builds_setka_search_query(self) -> None:
        self.assertEqual(build_setka_search_query("dns"), "dns site:setka.ru/companies")
        queries = build_setka_search_queries("dns", ("yandex", "google"))

        self.assertEqual(len(queries), 2)
        self.assertEqual(queries[0].query, "dns site:setka.ru/companies")
        self.assertEqual(queries[0].url, build_search_url("yandex", queries[0].query))
        self.assertEqual(queries[0].engine, "yandex")
        self.assertEqual(queries[1].engine, "google")

    def test_validates_company_networks_url(self) -> None:
        self.assertTrue(is_setka_company_networks_url("https://setka.ru/companies/dns/networks"))
        self.assertTrue(is_setka_company_networks_url("https://setka.ru/companies/dns/networks?x=1"))
        self.assertFalse(is_setka_company_networks_url("https://setka.ru/companies/dns"))
        self.assertFalse(is_setka_company_networks_url("http://setka.ru/companies/dns/networks"))
        self.assertFalse(is_setka_company_networks_url("https://example.ru/companies/dns/networks"))

    def test_matches_company_identity_on_network_page(self) -> None:
        html = """
        <title>Сетки компании DNS | Сетка</title>
        <meta property="og:title" content="Сетки компании DNS">
        <h1>сетки компании DNS</h1>
        """

        self.assertIn("DNS", extract_setka_company_identity(html))
        self.assertTrue(setka_company_page_matches("dns", html))
        self.assertFalse(setka_company_page_matches("эльдорадо", html))

        cyrillic_html = '<title>Сетки компании Микран | Сетка</title>'
        self.assertTrue(setka_company_page_matches("Микран", cyrillic_html))
        self.assertFalse(setka_company_page_matches("micran", cyrillic_html))

    def test_extracts_network_ids_and_members_url(self) -> None:
        html = """
        <a data-analytics-event-value="{&quot;event_label&quot;: &quot;my_network&quot;}">nav</a>
        <a data-analytics-event-value="{&quot;event_label&quot;: &quot;019bff06-31ec-70d0-aaaf-9a0b1725626b&quot;}">network</a>
        <a data-analytics-event-value="{&quot;event_label&quot;: &quot;create&quot;}">create</a>
        <a href="/networks/123">main</a>
        <a href="https://setka.ru/networks/team_2/members">members</a>
        <a href="/networks/123">duplicate</a>
        <div hx-get="/companies/company-id/networks/load-more/2">more</div>
        """

        self.assertEqual(
            extract_setka_network_ids(html),
            ("019bff06-31ec-70d0-aaaf-9a0b1725626b", "123", "team_2"),
        )
        self.assertEqual(
            build_setka_members_url("019bff06-31ec-70d0-aaaf-9a0b1725626b"),
            "https://setka.ru/networks/019bff06-31ec-70d0-aaaf-9a0b1725626b/members",
        )
        self.assertEqual(build_setka_members_url("team_2"), "https://setka.ru/networks/team_2/members")

    def test_extracts_setka_network_load_more_urls(self) -> None:
        html = """
        <div hx-get="/companies/dns/networks/load-more/1">more networks</div>
        <button hx-get="/networks/123/members/load-more?working_type=working_now">more members</button>
        """

        self.assertEqual(
            extract_setka_network_load_more_urls(html, "https://setka.ru/companies/dns/networks"),
            ("https://setka.ru/companies/dns/networks/load-more/1",),
        )

    def test_extracts_people_only_from_hx_swap_inner_html(self) -> None:
        html = f"""
        <div>{PETR_PETROV}</div>
        <section hx-swap="innerHTML">
          {IVAN_IVANOV}
          <span>{ANNA_SMIRNOVA}</span>
        </section>
        """

        people = extract_setka_people(html)

        self.assertEqual(len(people), 2)
        self.assertEqual(people[0].firstname, "\u0418\u0432\u0430\u043d")
        self.assertEqual(people[0].lastname, "\u0418\u0432\u0430\u043d\u043e\u0432")
        self.assertEqual(people[1].firstname, "\u0410\u043d\u043d\u0430")
        self.assertEqual(people[1].lastname, "\u0421\u043c\u0438\u0440\u043d\u043e\u0432\u0430")

    def test_extracts_people_from_working_now_members_user_links(self) -> None:
        html = f"""
        <a href="https://setka.ru/users/outside" hx-swap="innerHTML">{PETR_PETROV}</a>
        <div id="working_now_members">
          <article>
            <img src="/avatar.png">
            <a class="cursor-pointer subtitle-2-semibold break-word line-clamp-2 whitespace-pre-line"
               href="https://setka.ru/users/cd6c0bff-69c4-436a-9705-d336f5023bd0"
               hx-get="/users/cd6c0bff-69c4-436a-9705-d336f5023bd0"
               hx-push-url="/users/cd6c0bff-69c4-436a-9705-d336f5023bd0"
               hx-target="body"
               hx-swap="innerHTML">{IVAN_IVANOV}</a>
          </article>
          <a href="/users/anna" hx-swap="innerHTML">{ANNA_SMIRNOVA}</a>
          <a href="/users/yana" hx-swap="innerHTML">{YANA_KIZNER}</a>
          <a href="/users/pavel" hx-swap="innerHTML">{PAVEL_EPHIMOV}</a>
        </div>
        """

        people = extract_setka_people(html)

        self.assertEqual(len(people), 4)
        self.assertEqual(people[0].lastname, "\u0418\u0432\u0430\u043d\u043e\u0432")
        self.assertEqual(people[1].lastname, "\u0421\u043c\u0438\u0440\u043d\u043e\u0432\u0430")
        self.assertEqual(people[2].firstname, "\u042f\u043d\u0430")
        self.assertEqual(people[2].lastname, "\u041a\u0438\u0437\u043d\u0435\u0440")
        self.assertEqual(people[3].firstname, "Pavel")
        self.assertEqual(people[3].lastname, "Ephimov")

    def test_empty_working_now_does_not_fallback_to_worked_previously(self) -> None:
        html = f"""
        <p>работают сейчас</p>
        <div id="working_now_members">
          <button hx-swap="innerHTML" hx-target="#working_now_members">скрыть</button>
        </div>
        <p>работали раньше</p>
        <div id="worked_previously_members">
          <a class="cursor-pointer subtitle-2-semibold"
             href="https://setka.ru/users/old"
             hx-get="/users/old"
             hx-swap="innerHTML">{IVAN_IVANOV}</a>
        </div>
        """

        self.assertEqual(extract_setka_people(html), ())

    def test_collects_people_from_setka_members_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            queries = build_setka_search_queries("dns", ("yandex",))
            search_url = queries[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            first_members_url = "https://setka.ru/networks/123/members"
            second_members_url = "https://setka.ru/networks/team_2/members"
            fetcher = FakeSetkaFetcher(
                {
                    search_url: f'<a href="{networks_url}">DNS networks</a>',
                    networks_url: '<title>Сетки компании DNS</title><a href="/networks/123">one</a><a href="/networks/team_2">two</a>',
                    first_members_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
                    second_members_url: f'<div id="working_now_members"><a href="/users/anna">{ANNA_SMIRNOVA}</a></div>',
                }
            )
            config = AutoConfig(
                search_engines=("yandex",),
                search_results_dir=root / "search_results",
                browser_pages_dir=root / "site_pages",
                log_path=None,
            )

            result = collect_setka_people("dns", config, fetcher=fetcher)

        self.assertEqual(len(result.people), 2)
        self.assertIn(networks_url, result.visited_urls)
        self.assertIn(first_members_url, result.visited_urls)
        self.assertIn(second_members_url, result.visited_urls)
        self.assertEqual(fetcher.rendered_urls, [search_url, networks_url, first_members_url, second_members_url])

    def test_setka_page_limit_stops_before_extra_members_and_load_more(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            search_url = build_setka_search_queries("dns", ("yandex",))[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            first_url = build_setka_members_url("first")
            fetcher = FakeSetkaFetcher({
                search_url: f'<a href="{networks_url}">DNS</a>',
                networks_url: (
                    '<title>Сетки компании DNS</title>'
                    '<a href="/networks/first">first</a>'
                    '<a href="/networks/second">second</a>'
                    '<div hx-get="/companies/dns/networks/load-more/1">more</div>'
                ),
                first_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
            })
            result = collect_setka_people(
                "dns",
                AutoConfig(
                    setka_max_pages=1,
                    search_results_dir=root / "search_results",
                    browser_pages_dir=root / "site_pages",
                ),
                fetcher=fetcher,
            )

        self.assertEqual(len(result.people), 1)
        self.assertEqual(fetcher.rendered_urls, [search_url, networks_url, first_url])

    def test_setka_page_limit_caps_listing_pages_too(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            search_url = build_setka_search_queries("dns", ("yandex",))[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            load_more_url = "https://setka.ru/companies/dns/networks/load-more/1"
            first_url = build_setka_members_url("first")
            second_url = build_setka_members_url("second")
            fetcher = FakeSetkaFetcher({
                search_url: f'<a href="{networks_url}">DNS</a>',
                networks_url: (
                    '<title>Сетки компании DNS</title>'
                    '<div hx-get="/companies/dns/networks/load-more/1">more</div>'
                ),
                load_more_url: (
                    '<a href="/networks/first">first</a><a href="/networks/second">second</a>'
                    '<div hx-get="/companies/dns/networks/load-more/2">more</div>'
                ),
                first_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
                second_url: f'<div id="working_now_members"><a href="/users/anna">{ANNA_SMIRNOVA}</a></div>',
            })
            result = collect_setka_people(
                "dns",
                AutoConfig(
                    setka_max_pages=2,
                    search_results_dir=root / "search_results",
                    browser_pages_dir=root / "site_pages",
                ),
                fetcher=fetcher,
            )

        self.assertEqual(len(result.people), 2)
        self.assertEqual(fetcher.rendered_urls, [search_url, networks_url, load_more_url, first_url, second_url])

    def test_collects_setka_networks_from_load_more_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            queries = build_setka_search_queries("dns", ("yandex",))
            search_url = queries[0].url
            networks_url = "https://setka.ru/companies/dns/networks"
            load_more_url = "https://setka.ru/companies/dns/networks/load-more/1"
            first_members_url = "https://setka.ru/networks/123/members"
            second_members_url = "https://setka.ru/networks/team_2/members"
            third_members_url = "https://setka.ru/networks/team_3/members"
            fetcher = FakeSetkaFetcher(
                {
                    search_url: f'<a href="{networks_url}">DNS networks</a>',
                    networks_url: (
                        '<title>РЎРµС‚РєРё РєРѕРјРїР°РЅРёРё DNS</title>'
                        '<a href="/networks/123">one</a>'
                        '<div hx-get="/companies/dns/networks/load-more/1">more</div>'
                    ),
                    load_more_url: '<a href="/networks/team_2">two</a><a href="/networks/team_3">three</a>',
                    first_members_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
                    second_members_url: f'<div id="working_now_members"><a href="/users/anna">{ANNA_SMIRNOVA}</a></div>',
                    third_members_url: f'<div id="working_now_members"><a href="/users/petr">{PETR_PETROV}</a></div>',
                }
            )
            config = AutoConfig(
                search_engines=("yandex",),
                search_results_dir=root / "search_results",
                browser_pages_dir=root / "site_pages",
                log_path=None,
            )

            result = collect_setka_people("dns", config, fetcher=fetcher)

        self.assertEqual(len(result.people), 3)
        self.assertIn(load_more_url, result.visited_urls)
        self.assertEqual(
            fetcher.rendered_urls,
            [search_url, networks_url, load_more_url, first_members_url, second_members_url, third_members_url],
        )

    def test_skips_setka_network_page_for_another_company(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            queries = build_setka_search_queries("эльдорадо", ("yandex", "google"))
            search_url = queries[0].url
            networks_url = "https://setka.ru/companies/burger/networks"
            members_url = "https://setka.ru/networks/123/members"
            fetcher = FakeSetkaFetcher(
                {
                    search_url: f'<a href="{networks_url}">Burger King networks</a>',
                    queries[1].url: f'<a href="{networks_url}">Burger King networks</a>',
                    networks_url: '<title>Сетки компании Burger King</title><a href="/networks/123">one</a>',
                    members_url: f'<div id="working_now_members"><a href="/users/ivan">{IVAN_IVANOV}</a></div>',
                }
            )
            config = AutoConfig(
                search_engines=("yandex", "google"),
                search_results_dir=root / "search_results",
                browser_pages_dir=root / "site_pages",
                log_path=None,
            )

            result = collect_setka_people("эльдорадо", config, fetcher=fetcher)

        self.assertEqual(result.people, ())
        self.assertEqual(result.visited_urls, ())
        self.assertIn(networks_url, result.skipped_urls)
        self.assertEqual(fetcher.rendered_urls, [search_url, queries[1].url, networks_url])
        self.assertTrue(any("looks like another company" in warning for warning in result.warnings))

    def test_ignores_wrong_setka_search_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            queries = build_setka_search_queries("dns", ("yandex",))
            search_url = queries[0].url
            fetcher = FakeSetkaFetcher(
                {
                    search_url: '<a href="https://setka.ru/companies/dns">wrong</a>',
                }
            )
            config = AutoConfig(
                search_engines=("yandex",),
                search_results_dir=root / "search_results",
                browser_pages_dir=root / "site_pages",
                log_path=None,
            )

            result = collect_setka_people("dns", config, fetcher=fetcher)

        self.assertEqual(result.people, ())
        self.assertEqual(result.visited_urls, ())
        self.assertIn("Setka company networks page was not found in search results.", result.warnings)
        self.assertEqual(fetcher.rendered_urls, [search_url])


if __name__ == "__main__":
    unittest.main()
