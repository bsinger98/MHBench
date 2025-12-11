"""
OpenStack Management Network Deployer

This module provides functionality to deploy management network infrastructure on OpenStack.
It creates a management network, attaches it to the router, creates security groups for
management access, and deploys a management host (bastion) for configuring internal hosts.
"""

import logging
from typing import Any, cast

import openstack.connection


class OpenstackManageNetworkDeployer:
    """Deploys management network infrastructure to OpenStack."""

    def __init__(
        self,
        connection: openstack.connection.Connection,
        router_name: str,
        manage_ssh_key_name: str,
        project_name: str = "perry",
    ):
        """
        Initialize the OpenStack management network deployer.

        Args:
            connection: OpenStack connection object
            project_name: Name of the OpenStack project/tenant
        """
        self.conn = connection
        self.project_name = project_name
        self.logger = logging.getLogger(__name__)

        # OpenStack typing is not great, so we need to cast services to Any
        self.network_service = cast(Any, connection.network)
        self.compute_service = cast(Any, connection.compute)

        # Management network configuration
        self.external_network_name = "external"
        self.management_network_name = "manage_network"
        self.management_subnet_name = "manage"
        self.management_cidr = "192.168.198.0/24"
        self.management_host_ip = "192.168.198.14"
        self.management_host_name = "manage_host"
        self.management_host_image_name = "Ubuntu20"
        self.management_host_flavor_name = "m1.small"

        self.talk_to_manage_sg_name = "talk_to_manage"
        self.manage_freedom_sg_name = "manage_freedom"

        self.manage_ssh_key_name = manage_ssh_key_name
        self.router_name = router_name
        self.router = self.network_service.find_router(router_name)
        if not self.router:
            raise Exception(f"Router {router_name} not found")

    def deploy_management_infrastructure(self):
        """
        Deploy complete management infrastructure including network, security groups, and host.

        Args:
            router_id: Optional router ID to attach to. If None, will find or create the main router.

        Returns:
            Dictionary containing deployed resource information
        """
        self.logger.info("Starting deployment of management infrastructure")

        # 1. Create security groups
        self._create_management_security_groups()

        # 2. Create management network
        network, subnet = self._create_management_network()

        # 3. Attach to router
        self._attach_to_router(subnet)

        # 4. Create management host
        self._create_management_host(network)

        self.logger.info("Management infrastructure deployment completed successfully")

    def _create_management_security_groups(self):
        """Create security groups for management network access."""
        self.logger.info("Creating management security groups")

        # Create talk_to_manage security group
        self.talk_to_manage_sg = self._create_talk_to_manage_security_group()

        # Create manage_freedom security group
        self.manage_freedom_sg = self._create_manage_freedom_security_group()

    def _create_talk_to_manage_security_group(self):
        """Create security group for communication with management network."""
        sg_name = self.talk_to_manage_sg_name

        # Check if security group already exists
        existing_sg = self.network_service.find_security_group(sg_name)
        if existing_sg:
            self.logger.info(f"Security group {sg_name} already exists")
            return existing_sg

        # Create security group
        sg = self.network_service.create_security_group(
            name=sg_name,
            description="Security group for communication with management network",
        )

        # SSH ingress from management network
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="ingress",
            protocol="tcp",
            port_range_min=22,
            port_range_max=22,
            remote_ip_prefix=self.management_cidr,
        )

        # SSH egress to management network
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="egress",
            protocol="tcp",
            port_range_min=22,
            port_range_max=22,
            remote_ip_prefix=self.management_cidr,
        )

        self.logger.info(f"Created security group: {sg_name}")
        return sg

    def _create_manage_freedom_security_group(self):
        """Create security group for full SSH access from management host."""
        sg_name = self.manage_freedom_sg_name

        # Check if security group already exists
        existing_sg = self.network_service.find_security_group(sg_name)
        if existing_sg:
            self.logger.info(f"Security group {sg_name} already exists")
            return existing_sg

        # Create security group
        sg = self.network_service.create_security_group(
            name=sg_name,
            description="Security group for full SSH access from management host",
        )

        # SSH ingress from anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="ingress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        # SSH egress to anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="egress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        self.logger.info(f"Created security group: {sg_name}")
        return sg

    def _create_management_network(self):
        """Create management network and subnet."""
        self.logger.info("Creating management network")

        # Check if network already exists
        existing_network = self.network_service.find_network(
            self.management_network_name
        )
        if existing_network:
            raise Exception(f"Network {self.management_network_name} already exists")

        # Create network
        network = self.network_service.create_network(
            name=self.management_network_name,
            admin_state_up=True,
            description="Management network for bastion host access",
        )

        # Create subnet
        subnet = self.network_service.create_subnet(
            name=self.management_subnet_name,
            network_id=network.id,
            ip_version=4,
            cidr=self.management_cidr,
            enable_dhcp=True,
            dns_nameservers=["8.8.8.8"],
        )

        self.logger.info(
            f"Created management network: {self.management_network_name} with subnet CIDR: {self.management_cidr}"
        )
        return network, subnet

    def _attach_to_router(self, subnet):
        """Attach management subnet to router."""
        self.logger.info("Attaching management network to router")

        # Add router interface
        self.network_service.add_interface_to_router(
            router=self.router.id, subnet_id=subnet.id
        )

        self.logger.info(f"Attached management subnet to router: {self.router.name}")

    def _create_management_host(self, network):
        """Create management host (bastion) with floating IP."""
        self.logger.info("Creating management host")

        # Check if host already exists
        existing_instance = self.compute_service.find_server(self.management_host_name)
        if existing_instance:
            raise Exception(
                f"Management host {self.management_host_name} already exists"
            )

        # Get image for Ubuntu 20
        image = self.compute_service.find_image(self.management_host_image_name)
        if not image:
            raise Exception(f"{self.management_host_image_name} image not found")

        # Get flavor (use m1.small or equivalent)
        flavor = self.compute_service.find_flavor(self.management_host_flavor_name)
        if not flavor:
            raise Exception(f"{self.management_host_flavor_name} flavor not found")

        # Create instance
        instance = self.compute_service.create_server(
            name=self.management_host_name,
            imageRef=image.id,
            flavorRef=flavor.id,
            networks=[{"uuid": network.id, "fixed_ip": self.management_host_ip}],
            security_groups=[
                {"name": self.talk_to_manage_sg.name},
                {"name": self.manage_freedom_sg.name},
            ],
            metadata={"role": "management", "type": "bastion"},
            key_name=self.manage_ssh_key_name,
        )

        # Wait for instance to become active
        instance = self.compute_service.wait_for_server(instance)
        self.logger.info(f"Created management host: {self.management_host_name}")

        # Create and associate floating IP
        floating_ip = self.network_service.create_ip(
            floating_network_id=self.network_service.find_network("external").id
        )

        # Find the port for the instance
        ports = list(self.network_service.ports(device_id=instance.id))
        if not ports:
            raise Exception(f"No ports found for instance {instance.id}")

        # Get the port with the management network IP
        management_port = None
        for port in ports:
            for fixed_ip in port.fixed_ips:
                if fixed_ip.get("ip_address") == self.management_host_ip:
                    management_port = port
                    break
            if management_port:
                break

        if not management_port:
            raise Exception(f"No port found with IP {self.management_host_ip}")

        # Associate floating IP with the instance port using network service
        self.network_service.update_ip(
            floating_ip,
            port_id=management_port.id,
            fixed_ip_address=self.management_host_ip,
        )

        self.logger.info(
            f"Associated floating IP {floating_ip.floating_ip_address} with management host"
        )

        return instance, floating_ip
