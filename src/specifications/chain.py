import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
)
from ansible.common import CreateUser
from ansible.goals import AddData

from src.environment import Environment
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker

fake = Faker()

NUMBER_RING_HOSTS = 25


class ChainEnvironment(Environment):
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
        log_event("Deployment Instace", "Setting up ICS network")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.ring_hosts[0].ip))
        time.sleep(3)

        # Setup users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        action = SetupServerSSHKeys(
            self.attacker_host.ip,
            self.attacker_host.users[0],
            self.ring_hosts[0].ip,
            self.ring_hosts[0].users[0],
        )
        self.ansible_runner.run_playbook(action)

        # Create ring of credentials
        for i, host in enumerate(self.ring_hosts):
            if i == len(self.ring_hosts) - 1:
                break
            else:
                action = SetupServerSSHKeys(
                    host.ip,
                    host.users[0],
                    self.ring_hosts[i + 1].ip,
                    self.ring_hosts[i + 1].users[0],
                )
            self.ansible_runner.run_playbook(action)

        # Add fake data to each host
        for host in self.network.get_all_hosts():
            self.ansible_runner.run_playbook(
                AddData(host.ip, host.users[0], f"~/data_{host.name}.json")
            )
