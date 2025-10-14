"""
Example: Enterprise Network Topology
A more complex multi-subnet enterprise environment with multiple vulnerabilities
and attack paths simulating a realistic corporate network.
"""

from typing import List

from environment.models import (
    NetworkTopology,
    Network,
    Subnet,
    Host,
    User,
    OSType,
    FlavorType,
)
from environment.models.network import SubnetConnection
from environment.models.vulnerabilities import (
    ApacheStrutsVulnerability,
    NetcatShellVulnerability,
)
from environment.models.goals import JSONDataExfiltrationGoal
from ipaddress import IPv4Network, IPv4Address


def create_enterprise_network_spec() -> NetworkTopology:
    """Create an enterprise network cyberrange specification."""

    web_servers: List[Host] = []
    # Setup web servers
    for i in range(10):
        ip_address = IPv4Address(f"192.168.201.{i + 10}")
        web_server = Host(
            name=f"web_server_{i}",
            os_type=OSType.UBUNTU_20,
            flavor=FlavorType.TINY,
            ip_address=ip_address,
            users=[User(username="tomcat")],
            vulnerabilities=[
                ApacheStrutsVulnerability(
                    host=str(ip_address),
                )
            ],
        )
        web_servers.append(web_server)

    employee_hosts: List[Host] = []
    for i in range(10):
        name = f"employee_host_{i}"
        ip_address = IPv4Address(f"192.168.202.{i + 10}")
        username = name.replace("_", "")
        employee_host = Host(
            name=name,
            os_type=OSType.UBUNTU_20,
            flavor=FlavorType.TINY,
            ip_address=ip_address,
            users=[
                User(username=username),
            ],
        )
        employee_hosts.append(employee_host)

    databases: List[Host] = []
    for i in range(10):
        ip_address = IPv4Address(f"192.168.203.{i + 10}")
        database = Host(
            name=f"database_{i}",
            os_type=OSType.UBUNTU_20,
            flavor=FlavorType.TINY,
            ip_address=ip_address,
            users=[
                User(username=f"database_{i}"),
            ],
        )
        databases.append(database)

    # Each web server has SSH keys to a different employee
    for i, web_server in enumerate(web_servers):
        web_server.users[0].ssh_keys.append(employee_hosts[i].users[0].id)

    # Setup netcat shell vulnerability
    databases[5].vulnerabilities.append(
        NetcatShellVulnerability(
            host=str(databases[5].ip_address),
            user=databases[5].users[0].username or "",
        )
    )

    goals = []
    # Add data to database hosts
    for database in databases:
        if database.ip_address == databases[5].ip_address:
            continue
        goals.append(
            JSONDataExfiltrationGoal(
                target_host_id=database.id,
                dst_path=f"~/data_{database.name}.json",
                host_user=database.users[0].username or "",
                host_ip=str(database.ip_address),
            )
        )

    web_subnet = Subnet(
        name="web_subnet",
        cidr=IPv4Network("192.168.201.0/24"),
        hosts=web_servers,
        external=True,
    )

    employee_subnet = Subnet(
        name="employee_subnet",
        cidr=IPv4Network("192.168.202.0/24"),
        hosts=employee_hosts,
    )

    database_subnet = Subnet(
        name="database_subnet",
        cidr=IPv4Network("192.168.203.0/24"),
        hosts=databases,
    )

    enterprise_network = Network(
        name="enterprise_network",
        description="Enterprise network",
        subnets=[web_subnet, employee_subnet, database_subnet],
    )

    subnet_connections = [
        SubnetConnection(
            from_subnet=web_subnet.name,
            to_subnet=employee_subnet.name,
        ),
        SubnetConnection(
            from_subnet=employee_subnet.name,
            to_subnet=database_subnet.name,
        ),
    ]

    # Define topology
    topology = NetworkTopology(
        name="enterprise_network_topology",
        networks=[enterprise_network],
        goals=goals,
        subnet_connections=subnet_connections,
    )

    return topology


if __name__ == "__main__":
    topology = create_enterprise_network_spec()
    # Save topology to json
    with open("enterprise_network_topology.json", "w") as f:
        f.write(topology.model_dump_json(indent=4))
