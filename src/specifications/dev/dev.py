import time

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import (
    SetupSudoEdit,
    SetupWriteableSudoers,
    SetupSudoBaron,
    SetupSudoBypass,
    SetupWriteablePasswd,
    SetupNetcatShell,
)
from ansible.goals import AddData

from src.environment import Environment
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

NUMBER_RING_HOSTS = 5


class DevEnvironment(Environment):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="openstack_dev",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}

    def parse_network(self):
        self.hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="host"
        )

        for host in self.hosts:
            if host.name == "host_0":
                self.host0 = host
            if host.name == "host_1":
                self.privledge_box = host
            if host.name == "host_2":
                self.nc_box = host
            if host.name == "host_3":
                self.host3 = host
            if host.name == "host_4":
                self.host4 = host

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        dev_subnet = Subnet("dev_hosts", self.hosts, "dev_hosts")

        self.network = Network("ring_network", [dev_subnet])
        for host in self.network.get_all_hosts():
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_RING_HOSTS:
            raise Exception(
                f"Expected number of hosts mismatch. Expected {NUMBER_RING_HOSTS} but got {len(self.network.get_all_hosts())}"
            )

    def compile_setup(self):
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.hosts[0].ip))
        time.sleep(3)

        # Setup users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        ### NC Box setup ###
        self.ansible_runner.run_playbook(SetupNetcatShell(self.nc_box.ip, "host2"))
        self.ansible_runner.run_playbook(
            AddData(self.nc_box.ip, "root", "~/data_nc_box.json")
        )

        ### Privledge escalation box setup ###
        self.ansible_runner.run_playbook(
            SetupServerSSHKeys(
                self.attacker_host.ip, "root", self.privledge_box.ip, "host1"
            )
        )

        # Setup a privledge vulnerability
        self.ansible_runner.run_playbook(SetupSudoBaron(self.nc_box.ip))
        self.ansible_runner.run_playbook(SetupSudoEdit(self.privledge_box.ip))
        self.ansible_runner.run_playbook(SetupWriteableSudoers(self.host3.ip))
        self.ansible_runner.run_playbook(SetupSudoBypass(self.host4.ip))
        self.ansible_runner.run_playbook(SetupWriteablePasswd(self.host0.ip))

        self.ansible_runner.run_playbook(
            AddData(self.privledge_box.ip, "root", "~/data1.json")
        )
