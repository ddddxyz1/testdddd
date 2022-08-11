import argparse
import itertools
import inspect
import logging
from typing import List, Dict
from ssl import SSLError
import sys

import requests
from requests.auth import HTTPBasicAuth

UNHANDLED_ERROR="Unhandled error %s"
INVALID_CERT="Invalid cert on target"

session = requests.Session()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("inventory")


def get_servers_by_type(
    region: str, pod: str, server_type: str, ms_url: str, username: str, password: str
) -> List[Dict[str, str]]:
    """Retrieves list of servers from apigee management

    Args:
        region: apigee datacenter such as dc-1 or dc-2
        pod: pod such as central, analytics and gateway
        server_type: server's type such as router or management-server
        ms_url: management server URL with protocol
        username: management sysadmin user
        password: management sysadmin password

    Returns:
        A list of dictionaries containing 3 items each
        {
            'ipv4_address': internal server ip,
            'isUp': server isUp status (bool)
            'region': dc-1, dc-2...
        }

    Raises:
        ValueError

    """
    params = {
        "region": region,
        "type": server_type,
        "pod": pod,
    }
    logger.info(f"{inspect.stack()[0][3]}: Getting server with params {params}")
    http_auth = HTTPBasicAuth(username, password)
    try:
        server_req = session.get(f"{ms_url}/v1/servers", params=params, auth=http_auth)
    except SSLError:
        logger.error(INVALID_CERT)
        sys.exit(1)
    except Exception as e:
        logger.error(UNHANDLED_ERROR % e)
        sys.exit(1)
    if server_req.status_code != 200:
        raise ValueError("Failed to receive http 200")
    return [
        {"ipv4_address": s["internalIP"], "isUp": s["isUp"], "region": region}
        for s in server_req.json()
    ]


def get_server_groups(
    region_pod_map: Dict[str, str], ms_url: str, username: str, password: str
) -> Dict[str, List[Dict[str, str]]]:
    """Retrieves servers grouped by server type

    Args:
        region_pod_map: region to gateway pod mapping
        ms_url: management server URL with protocol
        username: management sysadmin user
        password: management sysadmin password

    Returns:
        A map of inventory server type to server list(get_servers_by_type)
        {
            'zkcs': [],
            'ms': []
            'router': get_servers_by_type(,,'router',,,)
            "mp": [],
            "qpid": [],
            "pg": [],
        }

    Raises:
        ValueError

    """
    servers: Dict[str, List[Dict[str, str]]] = {
        "zkcs": [],
        "ms": [],
        "router": [],
        "mp": [],
        "qpid": [],
        "pg": [],
    }
    server_type_map = {
        "zkcs": {"type": "apimodel-datastore", "pod": "central"},
        "ms": {"type": "management-server", "pod": "central"},
        "router": {"type": "router"},
        "mp": {"type": "message-processor"},
        "qpid": {"type": "qpid-server", "pod": "central"},
        "pg": {"type": "postgres-server", "pod": "analytics"},
    }
    for region, (server_type, type_data) in itertools.product(
        region_pod_map.keys(), server_type_map.items()
    ):
        pod = (
            type_data["pod"]
            if server_type not in ["router", "mp"]
            else region_pod_map[region]
        )
        logger.info(
            f"{inspect.stack()[0][3]}: Retrieving {server_type} nodes"
            f" from {region} region, {pod} pod"
        )

        servers[server_type].extend(
            get_servers_by_type(
                region,
                pod,
                type_data["type"],
                ms_url,
                username,
                password,
            )
        )
    logger.info(f"{inspect.stack()[0][3]}: Gathered all servers")
    return servers


def get_regions_pods(ms_url: str, username: str, password: str) -> Dict[str, str]:
    """Gets regions and associated gateway pod and returns a 1:1 map

    Args:
        ms_url: management server URL
        username: apigee sysadmin user
        password: apigee sysadmin password

    Returns:
        {
            region: gateway_pod
        }
    """
    logger.info(f"{inspect.stack()[0][3]}: Retrieving regions and pods")
    region_pod_map: Dict[str, str] = {}
    try:
        regions = session.get(
            f"{ms_url}/v1/regions", auth=HTTPBasicAuth(username, password)
        ).json()
    except SSLError:
        logger.error(INVALID_CERT)
        sys.exit(1)
    except Exception as e:
        logger.error(UNHANDLED_ERROR % e)
        sys.exit(1)
    for region in regions:
        try:
            pods = session.get(
                f"{ms_url}/v1/regions/{region}/pods",
                auth=HTTPBasicAuth(username, password),
            ).json()
        except SSLError:
            logger.error(INVALID_CERT)
            sys.exit(1)
        except Exception as e:
            logger.error(UNHANDLED_ERROR % e)
            sys.exit(1)
        else:
            pods.remove("central")
            pods.remove("analytics")
            if len(pods) != 1:
                raise ValueError(f"more than one gateway pods found {pods}")
            region_pod_map[region] = pods[0]
    return region_pod_map


requests.get("https://google.com", verify=False)

def main():  # pragma: no cover
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Provide required details to create inventory file"
    )
    parser.add_argument("--ms_url", help="Management URL", required=True)
    parser.add_argument("--username", help="provide sysadmin username", required=True)
    parser.add_argument("--password", help="provide sysadmin password", required=True)
    parser.add_argument(
        "--inventory", help="provide Inventory file location", required=True
    )
    parser.add_argument(
        "--ldap", help="provide ldap ip addresses in comma(,) separated", required=True
    )
    parser.add_argument(
        "--dev",
        help="Dev mode, no TLS verification",
        required=False,
        default="no",
        choices=["yes", "no"],
    )
    args = parser.parse_args()
    global session
    if args.dev == "yes":
        session.verify = False
    ldapservers = args.ldap.split(",")
    region_pod_map = get_regions_pods(args.ms_url, args.username, args.password)
    server_groups = get_server_groups(
        region_pod_map, args.ms_url, args.username, args.password
    )
    logger.info(
        f"{inspect.stack()[0][3]}: Generating inventory from server information"
    )
    inventory: List[str] = []
    for group, servers in server_groups.items():
        inventory.append(f"[{group}]")
        inventory.extend(f"{server['ipv4_address']}" for server in servers)
    inventory.append("[ldap]")
    inventory.extend(ldapservers)
    if len(ldapservers) > 0 and ldapservers[0] != "":
        inventory.append("")
    with open(args.inventory, "w", encoding="utf-8") as inventory_file:
        inventory_file.write("\n".join(inventory))
    logger.info(f"{inspect.stack()[0][3]}: Completed generating inventory")


if __name__ == "__main__":
    main()

