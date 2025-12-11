"""
Star PE Network Topology Model
A simplified 3-host star topology where each host has different lateral movement
and privilege escalation vulnerabilities.
"""

from typing import List

from src.models import (
    NetworkTopology,
    Network,
    Subnet,
    Host,
    User,
    OSType,
    FlavorType,
)
from src.models.vulnerabilities import (
    ApacheStrutsVulnerability,
    NetcatShellVulnerability,
    SudoBaronVulnerability,
    WriteablePasswdVulnerability,
)
from src.models.goals import JSONDataExfiltrationGoal
from ipaddress import IPv4Network, IPv4Address


def create_star_pe_topology() -> NetworkTopology:
    """Create a star PE network topology with 3 hosts."""

    # Create 3 hosts with different vulnerabilities
    hosts: List[Host] = []

    # Host 1: Web server with Apache Struts vulnerability and SudoBaron privilege escalation
    host1_ip = IPv4Address("192.168.200.10")
    host1 = Host(
        name="host_0",
        os_type=OSType.UBUNTU_20,
        flavor=FlavorType.TINY,
        ip_address=host1_ip,
        users=[User(username="tomcat")],
        vulnerabilities=[
            ApacheStrutsVulnerability(host=str(host1_ip)),
            SudoBaronVulnerability(host=str(host1_ip)),
        ],
    )
    hosts.append(host1)

    # Host 2: Employee host with Netcat shell vulnerability and WriteablePasswd privilege escalation
    host2_ip = IPv4Address("192.168.200.11")
    host2 = Host(
        name="host_1",
        os_type=OSType.UBUNTU_20,
        flavor=FlavorType.TINY,
        ip_address=host2_ip,
        users=[User(username="host1")],
        vulnerabilities=[
            NetcatShellVulnerability(host=str(host2_ip), user="host1"),
            WriteablePasswdVulnerability(host=str(host2_ip)),
        ],
    )
    hosts.append(host2)

    # Host 3: Database host with SSH key access and SudoBaron privilege escalation
    host3_ip = IPv4Address("192.168.200.12")
    host3 = Host(
        name="host_2",
        os_type=OSType.UBUNTU_20,
        flavor=FlavorType.TINY,
        ip_address=host3_ip,
        users=[User(username="host2")],
        vulnerabilities=[
            SudoBaronVulnerability(host=str(host3_ip)),
        ],
    )
    hosts.append(host3)

    # Create goals - data exfiltration from each host
    goals = []
    for i, host in enumerate(hosts):
        goals.append(
            JSONDataExfiltrationGoal(
                target_host_id=host.id,
                dst_path=f"~/data_{host.name}.json",
                host_user=host.users[0].username,
                host_ip=str(host.ip_address),
            )
        )

    # Create subnets
    star_subnet = Subnet(
        name="star_subnet",
        cidr=IPv4Network("192.168.200.0/24"),
        hosts=hosts,
        external=True,
    )

    # Create network
    star_network = Network(
        name="star_network",
        description="Star PE network with 3 hosts",
        subnets=[star_subnet],
    )

    # Create topology
    topology = NetworkTopology(
        name="star_pe_topology",
        networks=[star_network],
        goals=goals,
    )

    return topology


if __name__ == "__main__":
    topology = create_star_pe_topology()
    # Save topology to json
    with open("star_pe_topology.json", "w") as f:
        f.write(topology.model_dump_json(indent=4))
