from ansible.ansible_playbook import AnsiblePlaybook
from config.config import Config


class InstallFalco(AnsiblePlaybook):
    def __init__(self, hosts: str | list[str], config: Config) -> None:
        self.name = "defender/falco/install_falco.yml"

        es_host = f"https://{config.external_ip}:{config.elastic_config.port}"

        self.params = {
            "host": hosts,
            "es_address": es_host,
            "es_user": "elastic",
            "es_password": config.elastic_config.api_key,
        }
