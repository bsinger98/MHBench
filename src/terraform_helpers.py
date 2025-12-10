import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Iterator

from config.config import Config


@contextmanager
def _temporary_tfvars(config: Config) -> Iterator[str]:
    """Create a throwaway tfvars file for Terraform and clean it up afterwards."""
    terraform_vars = config.terraform_vars
    tfvars_content = "\n".join(
        f"{key} = {json.dumps(value)}" for key, value in terraform_vars.items()
    )

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".tfvars", delete=False, encoding="utf-8"
    )
    try:
        tmp_file.write(tfvars_content)
        tmp_file.flush()
        tmp_file.close()
        yield tmp_file.name
    finally:
        try:
            os.remove(tmp_file.name)
        except OSError:
            pass


def deploy_network(name: str, config: Config) -> None:
    deployment_dir = os.path.join("src/topologies", name)
    subprocess.run(
        ["terraform", "init"],
        cwd=deployment_dir,
        capture_output=True,
        text=True,
    )

    with _temporary_tfvars(config) as tfvars_path:
        process = subprocess.Popen(
            [
                "terraform",
                "apply",
                f"-var-file={tfvars_path}",
                "-auto-approve",
            ],
            cwd=deployment_dir,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        process.communicate()


def destroy_network(name: str, config: Config) -> None:
    deployment_dir = os.path.join("src/topologies", name)
    subprocess.run(
        ["terraform", "init"],
        cwd=deployment_dir,
        capture_output=True,
        text=True,
    )

    with _temporary_tfvars(config) as tfvars_path:
        process = subprocess.Popen(
            [
                "terraform",
                "destroy",
                f"-var-file={tfvars_path}",
                "-auto-approve",
            ],
            cwd=deployment_dir,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        process.communicate()
