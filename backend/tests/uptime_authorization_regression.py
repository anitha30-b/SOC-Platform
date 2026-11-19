"""Actual uptime routes with test identities and mocked HTTP checks."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from types import SimpleNamespace
    from unittest.mock import patch
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.testclient import TestClient
    import rbac
    import uptime

    app = FastAPI()
    app.include_router(uptime.router)

    def test_identity(x_test_user: str | None = Header(default=None)):
        identities = {
            "5": (5, None, 1),
            "6": (6, None, 1),
            "10": (10, 100, 1),
            "11": (11, 100, 1),
            "20": (20, 200, 1),
            "admin": (30, None, 3),
        }
        if x_test_user not in identities:
            raise HTTPException(401, "Authentication required")
        uid, client, role = identities[x_test_user]
        return SimpleNamespace(
            id=uid, client_id=client, role_id=role,
            username=f"user-{uid}",
        )

    app.dependency_overrides[rbac.get_current_user] = test_identity

    def sample(status="UP"):
        return {
            "status": status,
            "http_status": 200 if status == "UP" else 503,
            "latency_ms": 12.5,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }

    class UptimeTests(unittest.TestCase):
        URL = "https://authorized.example"

        def setUp(self):
            with uptime._monitors_lock:
                uptime.monitors.clear()
            self.client = TestClient(app)
            self.check_patch = patch.object(
                uptime, "check_website", side_effect=lambda url: sample()
            )
            self.check = self.check_patch.start()

        def tearDown(self):
            self.check_patch.stop()
            self.client.close()
            with uptime._monitors_lock:
                uptime.monitors.clear()

        def request(self, method, route, user="5", **params):
            headers = {"X-Test-User": user} if user else {}
            return self.client.request(
                method, "/uptime/" + route,
                params=params, headers=headers,
            )

        def start(self, user="5", name="Owner monitor", url=None):
            return self.request(
                "POST", "start", user,
                website_name=name, target_url=url or self.URL,
            )

        def status(self, user="5", url=None):
            params = {"target_url": url} if url else {}
            return self.request("GET", "status", user, **params)

        def test_authentication_required_on_all_routes(self):
            for method, route, params in (
                ("POST", "start", {
                    "website_name": "Test", "target_url": self.URL,
                }),
                ("POST", "check", {"target_url": self.URL}),
                ("GET", "status", {}),
                ("POST", "stop", {"target_url": self.URL}),
            ):
                response = self.request(method, route, None, **params)
                self.assertEqual(response.status_code, 401, response.text)
            self.check.assert_not_called()

        def test_wrong_role_denied_on_all_routes(self):
            for method, route, params in (
                ("POST", "start", {
                    "website_name": "Test", "target_url": self.URL,
                }),
                ("POST", "check", {"target_url": self.URL}),
                ("GET", "status", {}),
                ("POST", "stop", {"target_url": self.URL}),
            ):
                response = self.request(method, route, "admin", **params)
                self.assertEqual(response.status_code, 403, response.text)
            self.check.assert_not_called()

        def test_owner_start_and_status(self):
            response = self.start()
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["monitoring"])
            self.assertEqual(response.json()["total_requests"], 1)
            self.assertEqual(response.json()["uptime_percentage"], 100)
            self.assertEqual(
                self.status(url=self.URL).json()["website_name"],
                "Owner monitor",
            )

        def test_same_url_is_independent_between_accounts(self):
            self.start(name="First owner")
            self.start("6", name="Second owner")
            response = self.request(
                "POST", "check", target_url=self.URL
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(self.status().json()["total_requests"], 2)
            other = self.status("6").json()
            self.assertEqual(other["website_name"], "Second owner")
            self.assertEqual(other["total_requests"], 1)

        def test_other_owner_cannot_read_monitor(self):
            self.start()
            self.assertEqual(self.status("6").json(), {"monitoring": False})
            self.assertEqual(
                self.status("6", self.URL).json(),
                {"monitoring": False},
            )

        def test_other_owner_cannot_check_or_stop(self):
            self.start()
            self.check.reset_mock()
            for route in ("check", "stop"):
                response = self.request(
                    "POST", route, "6", target_url=self.URL
                )
                self.assertEqual(response.status_code, 404, response.text)
            self.check.assert_not_called()
            self.assertEqual(self.status().json()["total_requests"], 1)

        def test_same_client_does_not_share_monitors(self):
            self.start("10")
            self.assertEqual(self.status("11").json(), {"monitoring": False})
            for route in ("check", "stop"):
                response = self.request(
                    "POST", route, "11", target_url=self.URL
                )
                self.assertEqual(response.status_code, 404, response.text)
            self.assertTrue(self.status("10").json()["monitoring"])

        def test_default_status_returns_latest_owned_monitor(self):
            self.start(name="First", url="https://first.example")
            self.start(name="Second", url="https://second.example")
            self.start("6", name="Peer latest", url="https://peer.example")
            self.assertEqual(self.status().json()["website_name"], "Second")

        def test_start_existing_monitor_does_not_reset_or_recheck(self):
            self.start()
            self.request("POST", "check", target_url=self.URL)
            self.check.reset_mock()
            response = self.start(name="Replacement name")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["total_requests"], 2)
            self.assertEqual(response.json()["website_name"], "Owner monitor")
            self.check.assert_not_called()

        def test_stop_only_removes_owner_monitor(self):
            self.start()
            self.start("6")
            response = self.request("POST", "stop", target_url=self.URL)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(self.status().json(), {"monitoring": False})
            self.assertTrue(self.status("6").json()["monitoring"])
            self.assertEqual(
                self.request(
                    "POST", "stop", target_url=self.URL
                ).status_code,
                404,
            )

        def test_invalid_targets_rejected_before_network_check(self):
            for url in (
                "example.com", "ftp://example.com", "http://",
                "https://name:password@example.com",
                "http://example.com:invalid",
            ):
                with self.subTest(url=url):
                    response = self.start(url=url)
                    self.assertEqual(response.status_code, 400, response.text)
            self.check.assert_not_called()

        def test_blank_or_long_name_rejected(self):
            for name in ("   ", "X" * 201):
                response = self.start(name=name)
                self.assertEqual(response.status_code, 400, response.text)
            self.check.assert_not_called()

        def test_success_and_failure_counts(self):
            self.start()
            self.check.side_effect = lambda url: sample("DOWN")
            response = self.request("POST", "check", target_url=self.URL)
            self.assertEqual(response.status_code, 200, response.text)
            body = response.json()
            self.assertEqual(body["total_requests"], 2)
            self.assertEqual(body["successful_requests"], 1)
            self.assertEqual(body["failed_requests"], 1)
            self.assertEqual(body["uptime_percentage"], 50)

        def test_recent_history_is_bounded_but_totals_are_cumulative(self):
            self.start()
            for _ in range(101):
                response = self.request("POST", "check", target_url=self.URL)
                self.assertEqual(response.status_code, 200, response.text)
            body = self.status().json()
            self.assertEqual(body["total_requests"], 102)
            self.assertEqual(len(body["recent_checks"]), 100)

        def test_stop_during_check_does_not_restore_monitor(self):
            self.start()
            entered = Event()
            release = Event()

            def delayed_check(url):
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("Timed out waiting to release check")
                return sample()

            self.check.side_effect = delayed_check
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(
                    self.request, "POST", "check", "5",
                    target_url=self.URL,
                )
                try:
                    self.assertTrue(entered.wait(timeout=3))
                    stopped = self.request(
                        "POST", "stop", target_url=self.URL
                    )
                    self.assertEqual(stopped.status_code, 200, stopped.text)
                finally:
                    release.set()
                response = pending.result(timeout=5)

            self.assertEqual(response.status_code, 404, response.text)
            self.assertEqual(self.status().json(), {"monitoring": False})

        def test_real_check_helper_handles_http_and_connection_failure(self):
            # Bypass the outer helper mock while mocking requests itself.
            helper = self.check_patch.get_original()[0]
            # get_original now sees the patched helper, so use a small
            # independent source extraction of the actual function instead.
            import ast
            source = Path(uptime.__file__).read_text()
            tree = ast.parse(source)
            node = next(
                item for item in tree.body
                if isinstance(item, ast.FunctionDef)
                and item.name == "check_website"
            )
            namespace = dict(vars(uptime))
            exec(compile(
                ast.Module(body=[node], type_ignores=[]),
                uptime.__file__, "exec",
            ), namespace)
            helper = namespace["check_website"]

            with patch.object(uptime.requests, "get") as get:
                get.return_value = SimpleNamespace(ok=True, status_code=200)
                self.assertEqual(helper(self.URL)["status"], "UP")
                get.return_value = SimpleNamespace(ok=False, status_code=503)
                self.assertEqual(helper(self.URL)["status"], "DOWN")
                get.side_effect = uptime.requests.Timeout("Synthetic timeout")
                result = helper(self.URL)
                self.assertEqual(result["status"], "DOWN")
                self.assertIsNone(result["http_status"])
                self.assertNotIn("Synthetic timeout", result["error"])

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(UptimeTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
