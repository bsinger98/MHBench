"""
OpenStack Network Deployer

This module provides functionality to deploy network topologies on OpenStack.
It converts Perry network specifications into OpenStack infrastructure, treating
each subnet as a separate OpenStack network as requested.
"""

import logging
from typing import Any, cast

import openstack.connection

from src.models import NetworkTopology, Network, Subnet


class OpenstackNetworkDeployer:
    """Deploys network topologies to OpenStack infrastructure."""

    def __init__(
        self, connection: openstack.connection.Connection, project_name: str = "perry"
    ):
        """
        Initialize the OpenStack network deployer.

        Args:
            connection: OpenStack connection object
            project_name: Name of the OpenStack project/tenant
        """
        self.conn = connection
        self.project_name = project_name
        self.logger = logging.getLogger(__name__)
        # Openstack typing is not great, so we need to cast the network service to Any
        self.network_service = cast(Any, connection.network)
        # Track created networks for routing setup
        self.created_networks = []
        self.router_name = f"{project_name}_main_router"

    def deploy_topology(self, topology: NetworkTopology) -> None:
        """
        Deploy a complete network topology to OpenStack.

        Args:
            topology: NetworkTopology object to deploy
        """
        self.logger.info(f"Starting deployment of topology: {topology.name}")

        # Clear any previously tracked networks
        self.created_networks = []

        # 1. Deploy networks (treating each subnet as a network)
        self.logger.info("Deploying networks...")
        for network in topology.networks:
            self._deploy_network_as_networks(network)

        # 2. Set up routing between networks if specified
        self._setup_routing()

        # 3. Create security groups for subnet connections
        self._create_security_groups_for_subnet_connections(topology)

    def _deploy_network_as_networks(self, network: Network) -> None:
        """
        Deploy a Perry Network by creating separate OpenStack networks for each subnet.

        Args:
            network: Perry Network object

        """

        for subnet in network.subnets:
            os_network = self._create_openstack_network(
                name=f"{subnet.name}",
                description=f"Network for {subnet.name} (CIDR: {subnet.cidr})",
                cidr=str(subnet.cidr),
            )

            # Track the created network for routing
            self.created_networks.append(os_network)

            self.logger.info(
                f"Created OpenStack network: {os_network.name} for subnet: {subnet.name}"
            )

    def _create_openstack_network(
        self, name: str, description: str = "", cidr: str = ""
    ):
        """
        Create an OpenStack network with a subnet.

        Args:
            name: Network name
            description: Network description
            cidr: CIDR block for the subnet (e.g., "192.168.1.0/24")

        Returns:
            Created OpenStack network object
        """
        # Check if network already exists
        existing_network = self.network_service.find_network(name)
        if existing_network:
            raise ValueError(f"Network {name} already exists")

        # Create new network (without CIDR - that goes on the subnet)
        network = self.network_service.create_network(
            name=name, description=description, admin_state_up=True
        )

        # Create subnet within the network if CIDR is provided
        if cidr:
            subnet_name = f"{name}_subnet"
            _ = self.network_service.create_subnet(
                name=subnet_name,
                network_id=network.id,
                ip_version=4,
                cidr=cidr,
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8", "8.8.4.4"],
            )
            self.logger.info(f"Created subnet: {subnet_name} with CIDR: {cidr}")

        return network

    def _create_security_groups_for_subnet_connections(
        self, topology: NetworkTopology
    ) -> None:
        """
        Create security groups for subnet connections.

        Simplified version: assumes all connections are bidirectional TCP with all ports allowed.
        """
        self.logger.info("Creating security groups for subnet connections...")

        # Get all subnets in the topology
        all_subnets = topology.get_all_subnets()

        # Create a security group for each subnet
        for subnet in all_subnets:
            self._create_subnet_security_group(subnet, topology)

    def _create_subnet_security_group(
        self, subnet: Subnet, topology: NetworkTopology
    ) -> None:
        """
        Create a security group for a specific subnet based on its connections.
        """

        sg_name = subnet.sg_name
        # Check if security group already exists
        existing_sg = self.network_service.find_security_group(sg_name)
        if existing_sg:
            raise Exception(f"Security group {sg_name} already exists")

        # Create the security group
        sg = self.network_service.create_security_group(
            name=sg_name,
            description=f"Security group for {subnet.name} subnet (CIDR: {subnet.cidr})",
        )

        # If subnet is external, create a rule to allow all traffic
        if subnet.external:
            self._create_external_subnet_rules(sg.id)
        else:
            # Always allow internal subnet communication (same subnet)
            self._create_internal_subnet_rules(sg.id, subnet)

            # Find all subnets that this subnet can communicate with (bidirectional)
            connected_subnets = set()
            for conn in topology.subnet_connections:
                if conn.from_subnet == subnet.name:
                    connected_subnets.add(conn.to_subnet)
                elif conn.to_subnet == subnet.name:
                    connected_subnets.add(conn.from_subnet)

            # Create TCP rules for each connected subnet (all ports)
            for connected_subnet_name in connected_subnets:
                connected_subnet = topology.get_subnet_by_name(connected_subnet_name)
                if connected_subnet:
                    self._create_simple_tcp_rule(sg.id, connected_subnet)

    def _create_simple_tcp_rule(self, sg_id: str, source_subnet) -> None:
        """
        Create a simple TCP rule allowing all ports from source subnet.
        """
        # Create ingress rule
        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="ingress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix=str(source_subnet.cidr),
        )

        # Create egress rule
        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="egress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix=str(source_subnet.cidr),
        )

    def _create_internal_subnet_rules(self, sg_id: str, subnet: Subnet) -> None:
        """
        Create rules to allow internal TCP communication within the same subnet.
        """

        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="ingress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix=str(subnet.cidr),
        )

        # Allow all SSH traffic
        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="ingress",
            protocol="tcp",
            port_range_min=22,
            port_range_max=22,
            remote_ip_prefix="0.0.0.0/0",
        )

        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="egress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix=str(subnet.cidr),
        )

    def _create_external_subnet_rules(self, sg_id: str) -> None:
        """
        Create rules to allow all traffic from external subnet.
        """

        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="egress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        self.network_service.create_security_group_rule(
            security_group_id=sg_id,
            direction="ingress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

    def _setup_routing(self) -> None:
        """
        Set up routing between networks based on routing rules.
        Creates a router and connects all deployed networks to it.
        """

        # Create a simple router that connects all networks
        external_network_name = "external"
        external_network = self.network_service.find_network(external_network_name)
        if not external_network:
            raise Exception(f"External network {external_network_name} not found")

        # Check if router already exists
        existing_router = self.network_service.find_router(self.router_name)
        if existing_router:
            raise ValueError(f"Router {self.router_name} already exists")
        else:
            # Create router
            router = self.network_service.create_router(
                name=self.router_name,
                admin_state_up=True,
                external_gateway_info={
                    "network_id": external_network.id,
                },
            )

            # Add all networks to the router as interfaces
            for network in self.created_networks:
                # Find the subnet for this network
                subnets = list(self.network_service.subnets(network_id=network.id))
                for subnet in subnets:
                    # Add router interface
                    self.network_service.add_interface_to_router(
                        router=router.id, subnet_id=subnet.id
                    )
