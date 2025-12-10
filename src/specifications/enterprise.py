import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupStrutsVulnerability
from ansible.goals import AddData

from src.environment import Environment
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker
import random

fake = Faker()


class Enterprise(Environment):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="enterprise",
        number_of_hosts=20,
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}
        self.number_of_hosts = number_of_hosts

    def parse_network(self):
        self.branch_one = get_hosts_on_subnet(self.openstack_conn, "10.0.1.0/24")
        self.branch_two = get_hosts_on_subnet(self.openstack_conn, "10.0.2.0/24")
        self.branch_three = get_hosts_on_subnet(self.openstack_conn, "10.0.3.0/24")
        self.branch_four = get_hosts_on_subnet(self.openstack_conn, "10.0.4.0/24")

        for host in self.branch_one:
            host.users.append("tomcat")

        for host in self.branch_two:
            username = host.name.replace("_", "")
            host.users.append(username)

        for host in self.branch_three:
            username = host.name.replace("_", "")
            host.users.append(username)

        for host in self.branch_four:
            username = host.name.replace("_", "")
            host.users.append(username)

        branch_one_subnet = Subnet("branch_one", self.branch_one, "talk_to_manage")
        branch_two_subnet = Subnet("branch_two", self.branch_two, "talk_to_manage")
        branch_three_subnet = Subnet(
            "branch_three", self.branch_three, "talk_to_manage"
        )
        branch_four_subnet = Subnet("branch_four", self.branch_four, "talk_to_manage")

        self.network = Network(
            "equifax_network",
            [
                branch_one_subnet,
                branch_two_subnet,
                branch_three_subnet,
                branch_four_subnet,
            ],
        )

        if len(self.network.get_all_hosts()) != self.number_of_hosts:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {self.number_of_hosts} but got {len(self.network.get_all_hosts())}"
            )

    def compile_setup(self):
        log_event("Deployment Instace", "Setting up Equifax Instance")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.branch_one[0].ip))
        time.sleep(3)

        # Setup apache struts and vulnerability
        webserver_ips = [host.ip for host in self.branch_one]
        self.ansible_runner.run_playbook(SetupStrutsVulnerability(webserver_ips))

        # Setup users on corporte hosts
        for host in self.branch_two + self.branch_three + self.branch_four:
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        webserver_with_creds = random.choice(self.branch_one)
        for employee in self.branch_three + self.branch_four:
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    webserver_with_creds.ip, "tomcat", employee.ip, employee.users[0]
                )
            )

        # Add data to database hosts
        for database in self.branch_three + self.branch_four:
            self.ansible_runner.run_playbook(
                AddData(database.ip, database.users[0], f"~/data_{database.name}.json")
            )
