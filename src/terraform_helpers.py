import subprocess
import os


def deploy_network(
    name: str,
):
    deployment_dir = os.path.join("environment/topologies", name)
    subprocess.run(
        ["terraform", "init"], cwd=deployment_dir, capture_output=True, text=True
    )

    process = subprocess.Popen(
        [
            "terraform",
            "apply",
            "-var-file=../../credentials.tfvars",
            "-auto-approve",
        ],
        cwd=deployment_dir,
        stdout=subprocess.PIPE,
        universal_newlines=True,
    )

    _, _ = process.communicate()


def destroy_network(name: str):
    deployment_dir = os.path.join("environment/topologies", name)
    subprocess.run(
        ["terraform", "init"], cwd=deployment_dir, capture_output=True, text=True
    )

    process = subprocess.Popen(
        [
            "terraform",
            "destroy",
            "-var-file=../../credentials.tfvars",
            "-auto-approve",
        ],
        cwd=deployment_dir,
        stdout=subprocess.PIPE,
        universal_newlines=True,
    )

    _, _ = process.communicate()
