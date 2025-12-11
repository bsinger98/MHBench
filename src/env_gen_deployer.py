from src.openstack.network_deployer import OpenstackNetworkDeployer
from src.openstack.host_deployer import OpenstackHostDeployer
from src.openstack.manage_network_deployer import OpenstackManageNetworkDeployer
from src.openstack.attacker_network_deployer import (
    OpenstackAttackerNetworkDeployer,
)
from src.terraform_deployer import find_manage_server
from openstack.connection import Connection
from src.openstack.ansible_host_builder import OpenstackAnsibleHostBuilder
from config.config import Config
from ansible.ansible_runner import AnsibleRunner
from src.models import NetworkTopology
import time
from ansible.caldera.InstallAttacker import InstallAttacker
from src.openstack.imager import OpenstackImager
from src.openstack.cleaner import OpenstackCleaner


class EnvGenDeployer:
    """Orchestrator for OpenStack environment."""

    def __init__(
        self,
        config: Config,
        openstack_conn: Connection,
    ):
        self.config = config
        self.openstack_conn = openstack_conn
        self.project_name = "perry"

        self.imager = OpenstackImager(
            openstack_conn=self.openstack_conn,
        )

        self.network_deployer = OpenstackNetworkDeployer(
            connection=self.openstack_conn,
            project_name=self.project_name,
        )

        self.attacker_network_deployer = OpenstackAttackerNetworkDeployer(
            connection=self.openstack_conn,
            router_name=self.network_deployer.router_name,
            project_name=self.project_name,
            attacker_ssh_key_name=self.config.openstack_config.ssh_key_name,
        )

        self.cleaner = OpenstackCleaner(
            openstack_conn=self.openstack_conn,
        )

    def compile_environment(self, topology: NetworkTopology):
        self.cleaner.clean_environment()

        self.deploy_network(topology)
        self.deploy_management_network()
        self.deploy_attacker_network()

        # Deploy and setup hosts
        self.deploy_hosts(topology, use_base_image=True)
        self.setup_hosts(topology)

        self.imager.clean_snapshots()
        self.imager.save_all_snapshots()

    def deploy_environment(self, topology: NetworkTopology):
        self.cleaner.clean_environment()

        self.deploy_network(topology)
        self.deploy_management_network()
        self.deploy_attacker_network(use_base_image=False)

        self.deploy_hosts(topology, use_base_image=False)

    def deploy_network(self, topology: NetworkTopology):
        self.network_deployer.deploy_topology(topology)

    def deploy_management_network(self):
        self.manage_network_deployer = OpenstackManageNetworkDeployer(
            connection=self.openstack_conn,
            router_name=self.network_deployer.router_name,
            project_name=self.project_name,
            manage_ssh_key_name=self.config.openstack_config.ssh_key_name,
        )
        self.manage_network_deployer.deploy_management_infrastructure()

    def deploy_attacker_network(self, use_base_image=True):
        self.attacker_network_deployer.deploy_attacker_infrastructure(
            use_base_image=use_base_image
        )

    def runtime_setup(self):
        _, manage_ip = find_manage_server(self.openstack_conn)
        ansible_runner = AnsibleRunner(
            ssh_key_path=self.config.openstack_config.ssh_key_path,
            management_ip=manage_ip,
            ansible_dir="./ansible/",
            log_path="output",
        )

        install_trials = 3
        errors = 0

        for i in range(install_trials):
            try:
                attacker_host_ip = self.attacker_network_deployer.attacker_host_ip
                ansible_runner.run_playbook(
                    InstallAttacker(attacker_host_ip, "root", self.config.external_ip)
                )
                break
            except Exception as e:
                # Restore attacker host
                errors += 1
                time.sleep(15)

        if errors == install_trials:
            raise Exception(
                f"Failed to install attacker host after {install_trials} trials"
            )

    def deploy_hosts(self, topology: NetworkTopology, use_base_image: bool):
        host_deployer = OpenstackHostDeployer(
            connection=self.openstack_conn,
            manage_ssh_key_name=self.config.openstack_config.ssh_key_name,
            project_name=self.project_name,
            talk_to_manage_sg_name=self.manage_network_deployer.talk_to_manage_sg_name,
            topology=topology,
        )
        host_deployer.deploy_hosts(use_base_image=use_base_image)

    def setup_hosts(self, topology: NetworkTopology):
        _, manage_ip = find_manage_server(self.openstack_conn)
        ansible_runner = AnsibleRunner(
            ssh_key_path=self.config.openstack_config.ssh_key_path,
            management_ip=manage_ip,
            ansible_dir="./ansible/",
            log_path="output",
        )
        host_deployer = OpenstackAnsibleHostBuilder(
            connection=self.openstack_conn,
            ansible_runner=ansible_runner,
            topology=topology,
            config=self.config,
            attacker_host_ip=self.attacker_network_deployer.attacker_host_ip,
        )
        host_deployer.setup_hosts()
