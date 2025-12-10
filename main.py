import click
import importlib
import openstack
from datetime import datetime
import os
from types import SimpleNamespace

from config.config_service import ConfigService
from src.environment import Environment
from ansible.ansible_runner import AnsibleRunner

env_module = importlib.import_module("src.specifications")


def create_openstack_connection(openstack_cfg):
    """
    Build an OpenStack connection directly from the app config instead of
    relying on a clouds.yml entry.
    """
    return openstack.connect(
        auth_url=openstack_cfg.openstack_auth_url,
        username=openstack_cfg.openstack_username,
        password=openstack_cfg.openstack_password,
        project_name=openstack_cfg.project_name,
        region_name=openstack_cfg.openstack_region,
        user_domain_name="Default",
        project_domain_name="Default",
    )


@click.group()
@click.option("--type", help="The environment", required=True, type=str)
@click.option(
    "--config-file",
    help="Path to the MHBench configuration JSON",
    default="config/config.json",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
)
@click.pass_context
def env(ctx, type: str, config_file: str):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    experiment_dir = f"./output/misc/{timestamp}"
    # Create the experiment directory
    os.makedirs(experiment_dir, exist_ok=True)

    ctx.ensure_object(SimpleNamespace)
    config = ConfigService(config_file).get_config()
    ctx.obj.config = config
    ctx.obj.config_path = config_file

    openstack_conn = create_openstack_connection(config.openstack_config)
    ssh_key_path = os.path.expanduser(config.openstack_config.ssh_key_path)
    ansible_runner = AnsibleRunner(
        ssh_key_path,
        None,
        "./ansible/",
        experiment_dir,
        False,
    )

    # Deploy deployment instance
    deployment_instance_ = getattr(env_module, type)
    environment: Environment = deployment_instance_(
        ansible_runner,
        openstack_conn,
        ctx.obj.config.external_ip,
        ctx.obj.config,
    )
    # Add deployment instance to context
    ctx.obj.environment = environment


@env.command()
@click.pass_context
@click.option("--skip_network", help="Skip network setup", is_flag=True)
def setup(ctx, skip_network: bool):
    click.echo("Setting up the environment...")
    if skip_network:
        click.echo("Skipping network setup")
        ctx.obj.environment.find_management_server()
        ctx.obj.environment.parse_network()
        ctx.obj.environment.runtime_setup()
    else:
        ctx.obj.environment.deploy_topology()
        ctx.obj.environment.setup()
        ctx.obj.environment.runtime_setup()


@env.command()
@click.pass_context
@click.option("--skip_network", help="Skip network setup", is_flag=True)
@click.option("--skip_host", help="Skip host setup", is_flag=True)
def compile(ctx, skip_network: bool, skip_host: bool):
    click.echo("Compiling the environment (can take several hours)...")
    ctx.obj.environment.compile(not skip_network, not skip_host)


@env.command()
@click.pass_context
def teardown(ctx):
    click.echo("Tearing down the environment...")
    ctx.obj.environment.teardown()
    click.echo("Environment has been torn down")


@env.command()
@click.pass_context
def deploy_network(ctx):
    click.echo("Setting up network...")
    ctx.obj.environment.deploy_topology()


if __name__ == "__main__":
    # Entrypoint for the CLI
    env()
