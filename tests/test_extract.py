"""Grouped HTML extraction and robots-led bounded crawl."""

import unittest
from urllib.parse import urlsplit

from webrecon import http
from webrecon.extract import INVENTORY_CATEGORIES, extract_inventory


def response(url, status=200, body=b"", location=""):
    headers = {"content-type": ["text/html"]}
    if location:
        headers["location"] = [location]
    return http.Response(url=url, status=status, headers=headers, body=body,
                         prefix="saved-fixture", exit_code=0)


class FakeClient:
    def __init__(self, responder, limit=200):
        self.responder = responder
        self.max_requests = limit
        self.request_count = 0
        self.urls = []

    def fetch(self, url, label="response"):
        if self.request_count >= self.max_requests:
            raise http.BudgetExceeded("fixture request limit reached")
        self.request_count += 1
        self.urls.append(url)
        return self.responder(url)


class ExtractTests(unittest.TestCase):
    def test_nine_categories_are_normalized_and_traceable(self):
        page = "http://box.htb:8080/start"
        body = b"""<html><body>
          Contact alice@example.test or <a href="mailto:bob@example.test">Bob</a>.
          <a href="/about#section">About</a><a href="/about">Again</a>
          <link href="/site.CSS?v=1" rel="stylesheet">
          <a href="/manual.PDF?download=1">Manual</a>
          <script src="/app.JS?v=2"></script>
          <form method="POST" action="/send"><input type="hidden" name="csrf"></form>
          <img src="/photo.PNG" srcset="/small.webp 1x, /large.webp 2x">
          <video src="/movie.mp4" poster="/poster.jpg"><source src="/other.webm"></video>
          <audio><source src="/song.MP3" type="audio/mpeg"></audio>
          <!-- Remember carol@example.test -->
          </body></html>"""
        inventory = extract_inventory(page, body, "saved-response")
        self.assertEqual(tuple(inventory), INVENTORY_CATEGORIES)
        self.assertEqual({item["value"] for item in inventory["emails"]}, {
            "alice@example.test", "bob@example.test", "carol@example.test"})
        self.assertEqual([item["value"] for item in inventory["links"] if
                          item["value"] == "http://box.htb:8080/about"],
                         ["http://box.htb:8080/about"])
        self.assertEqual({item["value"] for item in inventory["external_files"]}, {
            "http://box.htb:8080/site.CSS?v=1",
            "http://box.htb:8080/manual.PDF?download=1"})
        self.assertEqual([item["value"] for item in inventory["js_files"]],
                         ["http://box.htb:8080/app.JS?v=2"])
        self.assertEqual(inventory["form_fields"], [{
            "value": "csrf", "source_url": page, "prefix": "saved-response",
            "tag": "input", "type": "hidden", "method": "post",
            "action": "http://box.htb:8080/send"}])
        self.assertEqual({item["value"] for item in inventory["images"]}, {
            "http://box.htb:8080/photo.PNG", "http://box.htb:8080/small.webp",
            "http://box.htb:8080/large.webp", "http://box.htb:8080/poster.jpg"})
        self.assertEqual({item["value"] for item in inventory["videos"]}, {
            "http://box.htb:8080/movie.mp4", "http://box.htb:8080/other.webm"})
        self.assertEqual([item["value"] for item in inventory["audio"]],
                         ["http://box.htb:8080/song.MP3"])
        self.assertEqual(inventory["comments"], [{
            "value": "<!-- Remember carol@example.test -->", "source_url": page,
            "prefix": "saved-response"}])
        for entries in inventory.values():
            for item in entries:
                self.assertEqual(item["source_url"], page)
                self.assertEqual(item["prefix"], "saved-response")

    def test_rejects_non_http_links_and_credentials(self):
        inventory = extract_inventory("http://box.htb/", b"""
          <a href="javascript:alert(1)">code</a>
          <a href="ftp://box.htb/file">ftp</a>
          <a href="http://user:password@box.htb/private">auth</a>
          <a href="mailto:user@example.test">email</a>
        """)
        self.assertEqual(inventory["links"], [])
        self.assertEqual([item["value"] for item in inventory["emails"]],
                         ["user@example.test"])

    def test_base_href_resolves_relative_links_and_assets(self):
        page = "http://box.htb:8080/start"
        inventory = extract_inventory(page, b'''
          <base href="https://assets.example.test/docs/">
          <a href="guide.html">Guide</a>
          <script src="../app.js"></script>
          <img src="images/logo.png">
        ''')
        self.assertIn("https://assets.example.test/docs/guide.html",
                      [item["value"] for item in inventory["links"]])
        self.assertEqual(inventory["js_files"][0]["value"],
                         "https://assets.example.test/app.js")
        self.assertEqual(inventory["images"][0]["value"],
                         "https://assets.example.test/docs/images/logo.png")

    def test_external_asset_hosts_are_discovered_without_following_them(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b'''
          <html><img src="https://cdn.example.test/logo.png">
          <link rel="stylesheet" href="https://static.example.test/app.css"></html>
        ''')
        client = FakeClient(lambda url: response(url, status=404, body=b"missing"))
        result = http.inspect_origin(origin, root, client, max_pages=1)
        names = {item["name"] for item in result["found_hosts"]}
        self.assertEqual(names, {"cdn.example.test", "static.example.test"})
        self.assertFalse(any("example.test" in url for url in client.urls))

    def test_standalone_named_input_has_no_invented_form_details(self):
        inventory = extract_inventory("http://box.htb/", b'<input name="q">')
        field = inventory["form_fields"][0]
        self.assertEqual(field["value"], "q")
        self.assertNotIn("method", field)
        self.assertNotIn("action", field)

    def test_document_archive_and_data_references_are_external_files(self):
        origin = "http://box.htb:8080/"
        inventory = extract_inventory(origin, b'''
          <a href="/manual.docx">Word</a><a href="/backup.zip">Archive</a>
          <a href="/dump.sql">Data</a><a href="/api.json">JSON</a>
        ''')
        self.assertEqual({item["value"] for item in inventory["external_files"]}, {
            origin + "manual.docx", origin + "backup.zip",
            origin + "dump.sql", origin + "api.json"})

    def test_robots_paths_are_crawled_with_original_service_port(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b"<html><title>Start</title></html>")

        def answer(url):
            path = urlsplit(url).path
            if path == "/robots.txt":
                return response(url, body=(b"User-agent: *\nAllow: /index-2.html\n"
                                           b"Disallow: /admin_h1dd3n\n"))
            if path == "/index-2.html":
                return response(url, body=b'<html><a href="/leaf">Next</a></html>')
            if path == "/admin_h1dd3n":
                return response(url, status=301,
                                location="http://box.htb/admin_h1dd3n/")
            if path == "/admin_h1dd3n/":
                return response(url, body=b"<html><!-- secret hint bob@example.test --></html>")
            if path == "/leaf":
                return response(url, body=b"<html>Leaf</html>")
            return response(url, status=404, body=b"missing")

        client = FakeClient(answer)
        emitted = []
        result = http.inspect_origin(origin, root, client, max_pages=5,
                                     max_depth=2, on_candidate=emitted.append)
        page_urls = [item["url"] for item in result["pages"]]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(page_urls), 5)
        self.assertIn(origin + "/index-2.html", page_urls)
        self.assertIn(origin + "/admin_h1dd3n/", page_urls)
        self.assertNotIn("http://box.htb/admin_h1dd3n/", client.urls)
        self.assertIn({"url": origin + "/index-2.html", "source": "robots_allow"},
                      result["candidate_urls"])
        self.assertIn({"url": origin + "/admin_h1dd3n", "source": "robots_disallow"},
                      result["candidate_urls"])
        self.assertEqual(result["inventory"]["comments"][0]["source_url"],
                         origin + "/admin_h1dd3n/")
        self.assertTrue(any(item.get("kind") == "inventory" and
                            item.get("category") == "emails" for item in emitted))

    def test_robots_paths_respect_page_limit(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b"<html>Start</html>")

        def answer(url):
            if urlsplit(url).path == "/robots.txt":
                return response(url, body=b"Allow: /next\nDisallow: /private\n")
            return response(url, status=404, body=b"missing")

        client = FakeClient(answer)
        result = http.inspect_origin(origin, root, client, max_pages=1)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["partial_reasons"], ["crawl_limit"])
        self.assertEqual([item["url"] for item in result["pages"]], [origin + "/"])
        self.assertNotIn(origin + "/next", client.urls)
        self.assertNotIn(origin + "/private", client.urls)
        self.assertEqual({item["url"] for item in result["candidate_urls"] if
                          item["source"] == "crawl_limit"},
                         {origin + "/next", origin + "/private"})

    def test_link_at_depth_boundary_remains_an_unfetched_candidate(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b'<html><a href="/one">One</a></html>')
        linked_pages = {
            "/one": b'<html><a href="/two">Two</a></html>',
            "/two": b'<html><a href="/three">Three</a></html>',
            "/three": b'<html><!-- clue --></html>',
        }

        def answer(url):
            body = linked_pages.get(urlsplit(url).path)
            return response(url, body=body) if body else response(url, status=404, body=b"missing")

        client = FakeClient(answer)
        result = http.inspect_origin(origin, root, client, max_pages=50, max_depth=2)
        self.assertEqual([item["url"] for item in result["pages"]],
                         [origin + "/", origin + "/one", origin + "/two"])
        self.assertTrue(any(item["url"] == origin + "/three"
                            for item in result["candidate_urls"]))
        self.assertEqual(result["status"], "partial")
        self.assertIn("depth_limit", result["partial_reasons"])
        self.assertNotIn(origin + "/three", client.urls)

    def test_default_crawl_reaches_clues_in_a_100_page_chain(self):
        origin = "http://box.htb:8080"

        def page_body(depth):
            parts = ["<html>"]
            if depth == 32:
                parts.append("<!-- depth 32 clue -->")
            if depth == 93:
                parts.append("Contact alice@example.test")
            if depth < 99:
                parts.append(f'<a href="/page-{depth + 1}">Next</a>')
            parts.append("</html>")
            return "".join(parts).encode()

        root = response(origin + "/", body=page_body(0))

        def answer(url):
            path = urlsplit(url).path
            number = path.removeprefix("/page-")
            if path.startswith("/page-") and number.isdecimal() and 1 <= int(number) <= 99:
                return response(url, body=page_body(int(number)))
            return response(url, status=404, body=b"missing")

        client = FakeClient(answer)
        result = http.inspect_origin(origin, root, client)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["pages"]), 100)
        self.assertEqual(result["pages"][-1]["url"], origin + "/page-99")
        self.assertEqual(result["inventory"]["comments"], [{
            "value": "<!-- depth 32 clue -->", "source_url": origin + "/page-32",
            "prefix": "saved-fixture"}])
        self.assertEqual(result["inventory"]["emails"], [{
            "value": "alice@example.test", "source_url": origin + "/page-93",
            "prefix": "saved-fixture"}])
        self.assertNotIn(origin + "/page-100", client.urls)

    def test_duplicate_robots_root_is_not_a_false_crawl_limit(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b"<html>Start</html>")

        def answer(url):
            if urlsplit(url).path == "/robots.txt":
                return response(url, body=b"Allow: /\nDisallow: /\n")
            return response(url, status=404, body=b"missing")

        result = http.inspect_origin(origin, root, FakeClient(answer), max_pages=1)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["url"] for item in result["pages"]], [origin + "/"])

    def test_root_links_get_page_budget_before_robots_paths(self):
        origin = "http://box.htb:8080"
        root = response(origin + "/", body=b'<html><a href="/from-root">Next</a></html>')

        def answer(url):
            if urlsplit(url).path == "/robots.txt":
                return response(url, body=b"Allow: /from-robots\n")
            if urlsplit(url).path == "/from-root":
                return response(url, body=b"<html>Linked page</html>")
            return response(url, status=404, body=b"missing")

        client = FakeClient(answer)
        result = http.inspect_origin(origin, root, client, max_pages=2)
        self.assertEqual([item["url"] for item in result["pages"]],
                         [origin + "/", origin + "/from-root"])
        self.assertNotIn(origin + "/from-robots", client.urls)
        self.assertIn({"url": origin + "/from-robots", "source": "crawl_limit"},
                      result["candidate_urls"])


if __name__ == "__main__":
    unittest.main()
