"""Shared-server defaults, explicit enablement and disabled firewall enforcement."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from startup_settings import STARTUP_VARIABLES, StartupSettings
import host_collector_runtime as collectors
import siem_response


class StartupControlsTests(unittest.TestCase):
    def test_shared_server_defaults_are_disabled(self):
        settings = StartupSettings.from_environment({})
        self.assertTrue(all(not getattr(settings, field) for field in STARTUP_VARIABLES))

    def test_each_control_can_be_enabled_independently(self):
        for selected, variable in STARTUP_VARIABLES.items():
            settings = StartupSettings.from_environment({variable: "true"})
            for field in STARTUP_VARIABLES:
                self.assertEqual(getattr(settings, field), field == selected)

    def test_invalid_control_is_rejected(self):
        for variable in STARTUP_VARIABLES.values():
            with self.assertRaisesRegex(ValueError, variable):
                StartupSettings.from_environment({variable: "perhaps"})

    def test_disabled_firewall_never_runs_a_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(siem_response.subprocess, "run") as run:
            self.assertFalse(siem_response.ensure_firewall_chain()["success"])
            self.assertFalse(siem_response.block_ip("192.0.2.1")["success"])
            with self.assertRaises(RuntimeError):
                siem_response._run_iptables("-S")
            run.assert_not_called()

    def test_enabled_firewall_retains_existing_execution_path(self):
        with patch.dict(os.environ, {"SOC_ENABLE_FIREWALL_OPERATIONS": "true"}), patch.object(
            siem_response.subprocess, "run", return_value=Mock(returncode=0)
        ) as run:
            self.assertTrue(siem_response.ensure_firewall_chain()["success"])
            self.assertTrue(run.called)

    def test_collector_shutdown_stops_only_owned_processes(self):
        process = Mock()
        process.poll.return_value = None
        with patch.object(collectors.subprocess, "Popen", return_value=process) as popen:
            collectors.reset_collectors()
            self.assertIs(collectors.spawn_collector(["synthetic-collector"]), process)
            collectors.stop_collectors()
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            with self.assertRaises(RuntimeError):
                collectors.spawn_collector(["must-not-start"])
            self.assertEqual(popen.call_count, 1)
        process.poll.return_value = 0
        collectors.reset_collectors()
        collectors.stop_collectors()


if __name__ == "__main__":
    unittest.main(verbosity=2)
