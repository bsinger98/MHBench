from pydantic import BaseModel


class ElasticSearchConfig(BaseModel):
    api_key: str
    port: int


class C2Config(BaseModel):
    api_key: str
    port: int
    external: bool = False
    python_path: str
    caldera_path: str


class OpenstackConfig(BaseModel):
    ssh_key_name: str
    ssh_key_path: str
    project_name: str
    openstack_username: str
    openstack_password: str
    openstack_region: str
    openstack_auth_url: str
    perry_key_name: str | None = None

    def to_terraform_vars(self) -> dict[str, str]:
        """Render the Terraform variable mapping expected by our modules."""
        perry_key = self.perry_key_name or self.ssh_key_name
        return {
            "project_name": self.project_name,
            "openstack_username": self.openstack_username,
            "openstack_password": self.openstack_password,
            "openstack_region": self.openstack_region,
            "openstack_auth_url": self.openstack_auth_url,
            "perry_key_name": perry_key,
        }


class Config(BaseModel):
    elastic_config: ElasticSearchConfig
    c2_config: C2Config | None = None
    openstack_config: OpenstackConfig
    external_ip: str
    experiment_timeout_minutes: int

    @property
    def terraform_vars(self) -> dict[str, str]:
        """Expose Terraform variables derived from the OpenStack config."""
        return self.openstack_config.to_terraform_vars()
