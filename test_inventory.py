import unittest
from unittest.mock import patch, MagicMock
from inventory import get_servers_by_type, get_regions_pods, get_server_groups
import json
from ssl import SSLError


class TestInventory(unittest.TestCase):
    @patch("inventory.session")
    def test_get_servers_by_type(self, mock_req):
        mock_response = MagicMock(
            status_code=200,
            json=lambda: json.loads(
                """[{
                    "externalHostName": "dt-dev-landscape-router-ip-192-168-12-109",
                    "externalIP": "192.168.12.109",
                    "internalHostName": "dt-dev-landscape-router-ip-192-168-12-109",
                    "internalIP": "192.168.12.109",
                    "isUp": true,
                    "pod": "gateway-1",
                    "reachable": true,
                    "region": "dc-1",
                    "tags": {
                        "property": [
                            {
                                "name": "router.http.ssl.default.enabled",
                                "value": "false"
                            },
                            {
                                "name": "config_transport",
                                "value": "HTTP1"
                            },
                            {
                                "name": "dp.color",
                                "value": "green"
                            },
                            {
                                "name": "cache_update_transport",
                                "value": "HTTP1"
                            },
                            {
                                "name": "release.id",
                                "value": "045100_01"
                            },
                            {
                                "name": "http.management.protocol",
                                "value": "HTTP2"
                            },
                            {
                                "name": "loadBalancer",
                                "value": "nginx"
                            },
                            {
                                "name": "default.profile.type",
                                "value": "router"
                            },
                            {
                                "name": "http.management.port",
                                "value": "8081"
                            },
                            {
                                "name": "rpm.name",
                                "value": "apigee-rpm-1.0.0.60168.2f35f3bed.2205200012-045100_01"
                            },
                            {
                                "name": "started.at",
                                "value": "1655815566941"
                            },
                            {
                                "name": "startup.interval",
                                "value": "202371"
                            },
                            {
                                "name": "rpc.port",
                                "value": "4527"
                            },
                            {
                                "name": "Profile",
                                "value": "Router"
                            },
                            {
                                "name": "startup.time",
                                "value": "3 minutes 22 seconds "
                            },
                            {
                                "name": "up.time",
                                "value": "1 day 15 hours 22 seconds"
                            }
                        ]
                    },
                    "type": [
                        "router"
                    ],
                    "uUID": "a31725f7-4e33-4dbc-900e-1083d86bbe13"
                }]"""
            ),
        )
        mock_req.get.return_value = mock_response
        servers_by_type = get_servers_by_type(
            "dc-1", "gateway", "router", "http://localhost:8080", "admin", "password"
        )
        self.assertEqual(len(servers_by_type), 1)

    @patch("inventory.session")
    def test_get_servers_by_type_ssl_exception(self, mock_req):
        mock_response = MagicMock(side_effect=SSLError)
        mock_req.get = mock_response
        with self.assertRaises(SystemExit):
            get_servers_by_type(
                "dc-1",
                "gateway",
                "router",
                "https://localhost:8080",
                "admin",
                "password",
            )

    @patch("inventory.session")
    def test_get_servers_by_type_generic_exception(self, mock_req):
        mock_response = MagicMock(side_effect=Exception)
        mock_req.get = mock_response
        with self.assertRaises(SystemExit):
            get_servers_by_type(
                "dc-1",
                "gateway",
                "router",
                "https://localhost:8080",
                "admin",
                "password",
            )

    @patch("inventory.session")
    def test_get_servers_by_type_not_200_ok(self, mock_req):
        mock_response = MagicMock(status_code=401)
        mock_req.get.return_value = mock_response
        with self.assertRaises(ValueError):
            get_servers_by_type(
                "dc-1",
                "gateway",
                "router",
                "https://localhost:8080",
                "admin",
                "password",
            )

    @patch("inventory.session")
    def test_get_regions_pods(self, mock_req):
        class Region:
            @staticmethod
            def json():
                return ["dc-1"]

        class Pod:
            @staticmethod
            def json():
                return ["analytics", "gateway-1", "central"]

        mock_res = MagicMock(side_effect=iter([Region, Pod]))
        mock_req.get = mock_res
        regions_pods = get_regions_pods("http://localhost", "admin", "password")
        self.assertEqual(len(regions_pods), 1)

    @patch("inventory.session")
    def test_get_regions_pods_region_ssl_exception(self, mock_req):
        mock_res = MagicMock(side_effect=SSLError)
        mock_req.get = mock_res
        with self.assertRaises(SystemExit):
            get_regions_pods("https://localhost", "admin", "password")

    @patch("inventory.session")
    def test_get_regions_pods_region_generic_exception(self, mock_req):
        mock_res = MagicMock(side_effect=Exception)
        mock_req.get = mock_res
        with self.assertRaises(SystemExit):
            get_regions_pods("https://localhost", "admin", "password")

    @patch("inventory.session")
    def test_get_regions_pods_pod_ssl_exception(self, mock_req):
        class Region:
            @staticmethod
            def json():
                return ["dc-1"]

        mock_res = MagicMock(side_effect=iter([Region, SSLError]))
        mock_req.get = mock_res
        with self.assertRaises(SystemExit):
            get_regions_pods("https://localhost", "admin", "password")

    @patch("inventory.session")
    def test_get_regions_pods_pod_generic_exception(self, mock_req):
        class Region:
            @staticmethod
            def json():
                return ["dc-1"]

        mock_res = MagicMock(side_effect=iter([Region, Exception]))
        mock_req.get = mock_res
        with self.assertRaises(SystemExit):
            get_regions_pods("https://localhost", "admin", "password")

    @patch("inventory.session")
    def test_get_regions_pods_pod_value_exception(self, mock_req):
        class Region:
            @staticmethod
            def json():
                return ["dc-1"]

        class Pod:
            @staticmethod
            def json():
                return ["analytics", "central"]

        mock_res = MagicMock(side_effect=iter([Region, Pod]))
        mock_req.get = mock_res
        with self.assertRaises(ValueError):
            get_regions_pods("https://localhost", "admin", "password")

    @patch("inventory.get_servers_by_type")
    def test_get_server_groups(self, m):
        side_effect = iter(
            [
                [
                    {"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.1"},
                    {"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.2"},
                    {"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.3"},
                ],
                [{"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.4"}],
                [{"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.5"}],
                [{"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.6"}],
                [{"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.7"}],
                [{"isUp": True, "region": "dc-1", "ipv4_address": "127.0.0.8"}],
            ]
        )
        m.side_effect = side_effect
        servers = get_server_groups(
            {"dc-1": "gateway-1"}, "http://localhost:8080", "admin", "password"
        )
        self.assertEqual(len(servers), 6)  # 6 server types
        self.assertEqual(
            list(servers.keys()), ["zkcs", "ms", "router", "mp", "qpid", "pg"]
        )
        self.assertEqual(len(servers["zkcs"]), 3)
