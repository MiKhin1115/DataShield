from unittest import TestCase
from unittest.mock import MagicMock, patch

from dlp_agent.evidence_vault import system_context


class SystemContextTests(TestCase):
    def test_active_routed_ipv4_is_listed_before_virtual_adapters(self) -> None:
        route_socket = MagicMock()
        route_socket.getsockname.return_value = ("192.168.100.146", 54321)
        adapter_results = [
            (2, 1, 6, "", ("172.23.160.1", 0)),
            (2, 1, 6, "", ("192.168.100.146", 0)),
        ]

        with (
            patch("dlp_agent.evidence_vault.socket.gethostname", return_value="WORKSTATION"),
            patch("dlp_agent.evidence_vault.socket.socket", return_value=route_socket),
            patch("dlp_agent.evidence_vault.socket.getaddrinfo", return_value=adapter_results),
        ):
            computer_name, addresses = system_context()

        self.assertEqual(computer_name, "WORKSTATION")
        self.assertEqual(addresses[0], "192.168.100.146")
        self.assertIn("172.23.160.1", addresses)
        route_socket.connect.assert_called_once_with(("8.8.8.8", 443))
        route_socket.close.assert_called_once()
