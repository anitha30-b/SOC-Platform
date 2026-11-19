import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hunting_identity import extract_message_identity


class HuntingIdentityTests(unittest.TestCase):
    def test_ssh_failed_invalid_account(self):
        result = extract_message_identity(
            "authentication_failure",
            "sshd[10]: Failed password for invalid user Alice from 192.0.2.1 port 22 ssh2",
        )
        self.assertEqual(result["username"], "Alice")
        self.assertEqual(result["identity_role"], "SSH attempted account")

    def test_ssh_failed_existing_account(self):
        result = extract_message_identity(
            "authentication_failure",
            "Failed password for root from 192.0.2.1 port 22 ssh2",
        )
        self.assertEqual(result["username"], "root")

    def test_ssh_invalid_user(self):
        result = extract_message_identity(
            "invalid_user", "Invalid user guest from 192.0.2.1 port 22"
        )
        self.assertEqual(result["username"], "guest")

    def test_ssh_accepted_account(self):
        result = extract_message_identity(
            "authentication",
            "Accepted publickey for anitha from 192.0.2.1 port 22 ssh2",
        )
        self.assertEqual(result["username"], "anitha")

    def test_sudo_session_target_is_not_actor(self):
        result = extract_message_identity(
            "privileged_session_opened",
            "pam_unix(sudo:session): session opened for user root(uid=0) by anitha(uid=1000)",
        )
        self.assertEqual(result["username"], "root")
        self.assertEqual(result["identity_role"], "sudo session target account")

    def test_sudo_closed_session(self):
        result = extract_message_identity(
            "privileged_session_closed",
            "pam_unix(sudo:session): session closed for user root",
        )
        self.assertEqual(result["username"], "root")

    def test_sudo_invoker_is_not_run_as_user(self):
        result = extract_message_identity(
            "privileged_command",
            "sudo[11]: anitha : TTY=pts/5 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id",
        )
        self.assertEqual(result["username"], "anitha")
        self.assertEqual(result["identity_role"], "sudo invoking account")

    def test_unrelated_event_is_not_parsed(self):
        self.assertIsNone(extract_message_identity(
            "dns_query", "Invalid user guest from 192.0.2.1"
        ))

    def test_free_text_is_not_an_identity(self):
        self.assertIsNone(extract_message_identity(
            "authentication_failure", "Report mentions user root"
        ))

    def test_malformed_account_is_rejected(self):
        self.assertIsNone(extract_message_identity(
            "authentication_failure",
            "Failed password for <script> from 192.0.2.1",
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
