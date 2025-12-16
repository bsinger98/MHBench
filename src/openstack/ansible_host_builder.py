"""
OpenStack Ansible Host Builder

This module provides functionality to configure deployed OpenStack hosts using
Ansible playbooks based on the network topology specifications. It maps topology
hosts to appropriate playbooks and executes them to configure users, vulnerabilities,
and other host-specific settings.
"""

import logging
from typing import List

import openstack.connection

from config.config import Config
from src.models import (
    NetworkTopology,
    Host,
    Goal,
    LateralMovementStep,
    PrivilegeEscalationStep,
)
from src.models.goals import DataExfiltrationGoal
from ansible.ansible_runner import AnsibleRunner
from ansible.ansible_playbook import AnsiblePlaybook

from ansible.deployment_instance import (
    InstallBasePackages,
    InstallKaliPackages,
)
from ansible.defender import InstallSysFlow


class OpenstackAnsibleHostBuilder:
    """Configures deployed OpenStack hosts using Ansible playbooks based on topology."""

    def __init__(
        self,
        connection: openstack.connection.Connection,
        ansible_runner: AnsibleRunner,
        topology: NetworkTopology,
        config: Config,
        attacker_host_ip: str,
    ):
        self.conn = connection
        self.logger = logging.getLogger(__name__)
        self.ansible_runner = ansible_runner
        self.topology = topology
        self.config = config
        self.attacker_host_ip = attacker_host_ip

    def setup_hosts(self, setup_base_dependencies: bool = True) -> None:
        """
        Setup all hosts in the topology.
        """
        if setup_base_dependencies:
            self.setup_base_dependencies()
        self.configure_topology_hosts(self.topology)

    def setup_base_dependencies(self, setup_sysflow: bool = False) -> None:
        """
        Setup base dependencies for the Ansible host builder.
        """
        self.logger.info("Setting up base dependencies for Ansible host builder")
        all_hosts = self.topology.get_all_hosts()
        all_host_ips = [str(host.ip_address) for host in all_hosts]

        # Install all base packages
        self.ansible_runner.run_playbook(InstallBasePackages(all_host_ips))

        # Install Kali packages on attacker host
        self.ansible_runner.run_playbook(InstallKaliPackages(self.attacker_host_ip))
        # Add SSH key to attacker host
        # Create SSH key for users
        ssh_key_playbook = AnsiblePlaybook(
            "deployment_instance/setup_server_ssh_keys/create_ssh_key.yml",
            self.attacker_host_ip,
        )
        ssh_key_playbook.params["host_user"] = "root"
        self.ansible_runner.run_playbook(ssh_key_playbook)

        if setup_sysflow:
            # Install sysflow on all hosts
            self.ansible_runner.run_playbook(InstallSysFlow(all_host_ips, self.config))

    def configure_topology_hosts(
        self, topology: NetworkTopology, run_async: bool = False
    ) -> None:
        """
        Configure all hosts in the topology using appropriate Ansible playbooks.

        This method handles dependencies properly by:
        1. Creating all users on all hosts first
        2. Setting up SSH keys between hosts (requires all users to exist)
        3. Configuring vulnerabilities and other host-specific settings

        Args:
            topology: Network topology containing hosts to configure
            run_async: Whether to run playbooks asynchronously
        """
        self.logger.info("Starting Ansible configuration of topology hosts")

        # Get all hosts from topology
        all_hosts = topology.get_all_hosts()

        if not all_hosts:
            self.logger.warning("No hosts found in topology")
            return

        # Phase 1: Create all users on all hosts first (dependency requirement)
        self.logger.info("Phase 1: Creating users on all hosts")
        user_playbooks = self._generate_user_creation_playbooks(all_hosts)
        self.ansible_runner.run_playbooks_serial(user_playbooks)

        # Phase 2: Set up SSH keys (requires all users to exist)
        self.logger.info("Phase 2: Setting up SSH keys between hosts")
        ssh_playbooks = self._generate_ssh_key_playbooks(all_hosts)
        self.ansible_runner.run_playbooks_serial(ssh_playbooks)

        # Phase 3: Configure vulnerabilities and other host-specific settings
        self.logger.info("Phase 3: Configuring vulnerabilities and other settings")
        # Legacy
        vuln_playbooks = self._generate_vuln_playbooks(all_hosts)
        # vuln_playbooks = self._generate_attack_path_playbooks()

        self.ansible_runner.run_playbooks_serial(vuln_playbooks)

        # Phase 4: Configure goals
        self.logger.info("Phase 4: Configuring goals")
        goal_playbooks = self._generate_goal_playbooks(topology.goals)
        self.ansible_runner.run_playbooks_serial(goal_playbooks)

        self.logger.info("Completed Ansible configuration of topology hosts")

    def _generate_user_creation_playbooks(
        self, all_hosts: List[Host]
    ) -> List[AnsiblePlaybook]:
        """
        Generate playbooks to create all users on all hosts.

        Args:
            all_hosts: List of all hosts in the topology

        Returns:
            List of user creation playbooks
        """
        playbooks = []

        for host in all_hosts:
            host_ip = str(host.ip_address) if host.ip_address else host.name

            for user in host.users:
                if user.username == "root":
                    continue

                user_playbook = AnsiblePlaybook(
                    "common/createUser/createUser.yml", host_ip
                )
                user_playbook.params["user"] = user.username
                user_playbook.params["password"] = user.password
                user_playbook.params["group"] = (
                    user.username
                )  # Create group with same name as user
                playbooks.append(user_playbook)

        for host in all_hosts:
            host_ip = str(host.ip_address)

            for user in host.users:
                # Create SSH key for users
                ssh_key_playbook = AnsiblePlaybook(
                    "deployment_instance/setup_server_ssh_keys/create_ssh_key.yml",
                    host_ip,
                )
                ssh_key_playbook.params["host_user"] = user.username
                playbooks.append(ssh_key_playbook)

        return playbooks

    def _generate_ssh_key_playbooks(
        self, all_hosts: List[Host]
    ) -> List[AnsiblePlaybook]:
        """
        Generate playbooks to set up SSH keys between hosts.
        This must be called after all users have been created.

        Args:
            all_hosts: List of all hosts in the topology

        Returns:
            List of SSH key setup playbooks
        """
        playbooks = []

        for host in all_hosts:
            host_ip = str(host.ip_address) if host.ip_address else host.name

            for user in host.users:
                # Add SSH keys if specified
                if user.ssh_keys:
                    for ssh_user_id in user.ssh_keys:
                        destination_user = self.topology.get_user_by_id(ssh_user_id)
                        if not destination_user:
                            raise Exception(f"User {ssh_user_id} not found")

                        destination_host = self.topology.get_host_by_user(
                            destination_user
                        )
                        if not destination_host:
                            raise Exception(f"Host for user {ssh_user_id} not found")

                        ssh_key_playbook = AnsiblePlaybook(
                            "deployment_instance/setup_server_ssh_keys/setup_ssh_keys.yml",
                            host_ip,
                        )
                        ssh_key_playbook.params["host"] = str(host.ip_address)
                        ssh_key_playbook.params["host_user"] = user.username
                        ssh_key_playbook.params["follower"] = str(
                            destination_host.ip_address
                        )
                        ssh_key_playbook.params["follower_user"] = (
                            destination_user.username
                        )
                        playbooks.append(ssh_key_playbook)

        return playbooks

    def _generate_attack_path_playbooks(self) -> List[AnsiblePlaybook]:
        """
        Generate playbooks to configure attack paths on the hosts.
        """
        playbooks = []

        for attack_path in self.topology.attack_paths:
            for step in attack_path.steps:
                if isinstance(step, LateralMovementStep):
                    if not step.vulnerability:
                        # Skip steps without assigned vulnerabilities
                        continue
                    to_host = self.topology.get_host_by_id(step.to_host_id)
                    if not to_host:
                        raise Exception(f"Host {step.to_host_id} not found")

                    playbook = AnsiblePlaybook(
                        step.vulnerability.playbook_path,
                        str(to_host.ip_address),
                    )
                    playbook.params.update(
                        step.vulnerability.model_dump(
                            mode="json", serialize_as_any=True
                        )
                    )
                    playbooks.append(playbook)

                elif isinstance(step, PrivilegeEscalationStep):
                    if not step.vulnerability:
                        # Skip steps without assigned vulnerabilities
                        continue
                    host = self.topology.get_host_by_id(step.host_id)
                    if not host:
                        raise Exception(f"Host {step.host_id} not found")

                    playbook = AnsiblePlaybook(
                        step.vulnerability.playbook_path,
                        str(host.ip_address),
                    )
                    playbook.params.update(
                        step.vulnerability.model_dump(
                            mode="json", serialize_as_any=True
                        )
                    )
                    playbooks.append(playbook)
        return playbooks

    def _generate_vuln_playbooks(self, all_hosts: List[Host]) -> List[AnsiblePlaybook]:
        """
        Generate playbooks for vulnerabilities and other host-specific configurations.

        Args:
            all_hosts: List of all hosts in the topology

        Returns:
            List of vulnerability and other configuration playbooks
        """
        playbooks = []

        for host in all_hosts:
            host_ip = str(host.ip_address) if host.ip_address else host.name
            # Configure vulnerabilities
            vuln_playbooks = self._get_vulnerability_playbooks(host, host_ip)
            playbooks.extend(vuln_playbooks)

        return playbooks

    def _get_vulnerability_playbooks(
        self, host: Host, host_ip: str
    ) -> List[AnsiblePlaybook]:
        """Generate playbooks to configure vulnerabilities on the host."""
        playbooks = []

        for vulnerability in host.vulnerabilities:
            playbook = AnsiblePlaybook(vulnerability.playbook_path, host_ip)
            playbook.params.update(
                vulnerability.model_dump(mode="json", serialize_as_any=True)
            )
            playbooks.append(playbook)

        return playbooks

    def _generate_goal_playbooks(self, goals: List[Goal]) -> List[AnsiblePlaybook]:
        """
        Generate playbooks to configure goals on the hosts.
        """
        playbooks = []

        for goal in goals:
            if isinstance(goal, DataExfiltrationGoal):
                playbook = AnsiblePlaybook(goal.playbook_path, goal.host_ip)
                playbook.params.update(
                    goal.model_dump(mode="json", serialize_as_any=True)
                )
                playbooks.append(playbook)

        return playbooks
