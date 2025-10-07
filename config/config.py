from pydantic import BaseModel


class ElasticSearchConfig(BaseModel):
    api_key: str
    port: int


class IncalmoConfig(BaseModel):
    path: str  # Path to the Incalmo project directory


class OpenstackConfig(BaseModel):
    ssh_key_name: str
    ssh_key_path: str


class Config(BaseModel):
    elastic_config: ElasticSearchConfig
    incalmo_config: IncalmoConfig
    openstack_config: OpenstackConfig
    external_ip: str
    experiment_timeout_minutes: int
