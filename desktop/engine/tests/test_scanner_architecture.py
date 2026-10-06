import asyncio
import unittest

from scanner.models import ScanProfile, ScannerCommand
from scanner.orchestrator import REGISTRY, run


class ScannerArchitectureTests(unittest.TestCase):
    def test_all_legacy_commands_are_registered(self):
        self.assertEqual(
            set(REGISTRY.commands()),
            {
                ScannerCommand.HEADERS,
                ScannerCommand.TLS,
                ScannerCommand.TECHNOLOGY,
                ScannerCommand.ASSESSMENT,
            },
        )

    def test_profile_values_are_explicit(self):
        self.assertEqual(ScanProfile.PASSIVE.value, "passive")
        self.assertEqual(ScanProfile.SAFE_ACTIVE.value, "safe_active")
        self.assertEqual(ScanProfile.DEEP.value, "deep")

    def test_unsupported_command_is_rejected(self):
        with self.assertRaises(ValueError):
            REGISTRY.get("not_a_scanner")

    def test_orchestrator_accepts_legacy_command_contract(self):
        operation = run(ScannerCommand.HEADERS.value, "https://example.com")
        self.assertTrue(asyncio.iscoroutine(operation))
        operation.close()


if __name__ == "__main__":
    unittest.main()
