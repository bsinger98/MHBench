import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.goals import AddData
from ansible.vulnerabilities import SetupSudoBaron, SetupWriteablePasswd
from ansible.vulnerabilities import SetupNetcatShell, SetupStrutsVulnerability

from src.terraform_deployer import TerraformDeployer
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker

fake = Faker()

NUMBER_RING_HOSTS = 25


class StarPE(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="star",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}

    def parse_network(self):
        self.star_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="host"
        )

        # Distribute hosts into 3 categories
        self.webservers = self.star_hosts[: len(self.star_hosts) // 3]

        self.nc_hosts = self.star_hosts[
            len(self.star_hosts) // 3 : 2 * len(self.star_hosts) // 3
        ]

        self.ssh_hosts = self.star_hosts[2 * len(self.star_hosts) // 3 :]

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]
        self.attacker_host.users.append("root")

        ringSubnet = Subnet("ring_network", self.star_hosts, "employee_one_group")
        self.network = Network("ring_network", [ringSubnet])

        # Setup tomcat users on all webservers
        for host in self.webservers:
            host.users.append("tomcat")

        # Setup normal users on all hosts
        for host in self.nc_hosts + self.ssh_hosts:
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_RING_HOSTS:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {NUMBER_RING_HOSTS} but got {len(self.network.get_all_hosts())}"
            )

    def compile_setup(self):
        log_event("Deployment Instace", "Setting up ICS network")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        time.sleep(3)

        # Phase A: create all users in parallel
        user_playbooks = [
            CreateUser(host.ip, user, "ubuntu")
            for host in self.network.get_all_hosts()
            for user in host.users
        ]
        self.ansible_runner.run_playbooks(user_playbooks)

        # Phase B: all remaining setup is independent — run in parallel
        phase_b_playbooks = [
            CreateSSHKey(host.ip, host.users[0]) for host in self.webservers
        ] + [
            SetupSudoBaron(self.star_hosts[i].ip)
            for i in range(0, len(self.star_hosts), 2)
        ] + [
            SetupWriteablePasswd(self.star_hosts[i].ip)
            for i in range(1, len(self.star_hosts), 2)
        ] + [
            SetupStrutsVulnerability(host.ip) for host in self.webservers
        ] + [
            SetupNetcatShell(host.ip, host.users[0]) for host in self.nc_hosts
        ] + [
            SetupServerSSHKeys(
                self.attacker_host.ip, self.attacker_host.users[0], host.ip, host.users[0]
            )
            for host in self.ssh_hosts
        ] + [
            AddData(host.ip, "root", f"~/data_{host.name}.json")
            for host in self.star_hosts
        ]
        self.ansible_runner.run_playbooks(phase_b_playbooks)
