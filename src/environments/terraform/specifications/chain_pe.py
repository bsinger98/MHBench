import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupSudoBaron, SetupWriteablePasswd
from ansible.goals import AddData

from src.terraform_deployer import TerraformDeployer
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker

fake = Faker()

NUMBER_RING_HOSTS = 25


class PEChainEnvironment(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="ring",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}

    def parse_network(self):
        self.ring_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="host"
        )

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]
        self.attacker_host.users.append("root")

        ringSubnet = Subnet("ring_network", self.ring_hosts, "employee_one_group")

        self.network = Network("ring_network", [ringSubnet])
        for host in self.network.get_all_hosts():
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_RING_HOSTS:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {NUMBER_RING_HOSTS} but got {len(self.network.get_all_hosts())}"
            )

    def compile_setup(self):
        log_event("Deployment Instace", "Setting up PE Chain network")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        time.sleep(3)

        # Phase A: PE vulns are independent of user creation — run in parallel
        ring_host_ips = [host.ip for host in self.ring_hosts]
        pe_playbooks = [
            SetupSudoBaron(ring_host_ips[i]) if i % 2 else SetupWriteablePasswd(ring_host_ips[i])
            for i in range(len(ring_host_ips))
        ]
        self.ansible_runner.run_playbooks(pe_playbooks)

        # Phase B1: create all users in parallel
        user_playbooks = [
            CreateUser(host.ip, user, "ubuntu", "ubuntu")
            for host in self.network.get_all_hosts()
            for user in host.users
        ]
        self.ansible_runner.run_playbooks(user_playbooks)

        # Phase B2: create SSH keys in parallel (requires users to exist)
        key_playbooks = [
            CreateSSHKey(host.ip, user)
            for host in self.network.get_all_hosts()
            for user in host.users
        ]
        self.ansible_runner.run_playbooks(key_playbooks)

        # Phase C: set up attacker→first host credential (single, must precede chain)
        self.ansible_runner.run_playbook(
            SetupServerSSHKeys(
                self.attacker_host.ip,
                self.attacker_host.users[0],
                self.ring_hosts[0].ip,
                self.ring_hosts[0].users[0],
            )
        )

        # Phase D: chain credentials and data in parallel (all independent)
        chain_and_data_playbooks = [
            SetupServerSSHKeys(
                self.ring_hosts[i].ip,
                self.ring_hosts[i].users[0],
                self.ring_hosts[i + 1].ip,
                self.ring_hosts[i + 1].users[0],
            )
            for i in range(len(self.ring_hosts) - 1)
        ] + [
            AddData(host.ip, "root", f"~/data_{host.name}.json")
            for host in self.network.get_all_hosts()
        ]
        self.ansible_runner.run_playbooks(chain_and_data_playbooks)
