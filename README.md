# MHBench

MHBench is a modular cybersecurity benchmarking framework for deploying, configuring, and testing complex network environments using automation tools like Terraform and Ansible. It supports a variety of topologies and vulnerability scenarios for research, training, and evaluation of security solutions.

## Features

- **Automated Environment Provisioning:** Uses Terraform and OpenStack to deploy virtualized environments with customizable topologies (e.g., ring, dumbbell, star, enterprise).
- **Ansible Automation:** Installs software, configures users, injects vulnerabilities, and sets up attack/defense scenarios using Ansible playbooks.
- **Vulnerability Injection:** Supports a wide range of vulnerabilities (e.g., privilege escalation, weak passwords, Apache Struts) for realistic attack simulations.
- **Data Generation:** Populates hosts with synthetic data for exfiltration and detection experiments.
- **Extensible Topologies:** Easily add or modify network layouts and host roles via Python specifications.

## Directory Structure

- `main.py` — Entry point for running MHBench.
- `ansible/` — Ansible playbooks, modules, and vulnerability scripts.
- `environment/` — Python modules for environment specifications and deployment logic.
- `config/` — Configuration files and templates.
- `utility/` — Helper scripts for OpenStack, logging, and other utilities.

## Getting Started

### Prerequisites

- Python 3.8+
- OpenStack environment (DevStack or Kolla)
- Terraform
- Ansible

### Setup

1. **Configure OpenStack:**
   - Use scripts in `utility/openstack_helper_functions/` to set up your OpenStack environment.
   - Update credentials in `environment/credentials_example.tfvars` and copy to `credentials.tfvars`.

2. **Deploy Environment:**
   - Navigate to the desired topology directory (e.g., `environment/topologies/dumbbell/`).
   - Run Terraform:
     ```sh
     terraform apply -var-file=../credentials.tfvars
     ```

3. **Run MHBench:**
   - Edit `config/config_example.json` as needed and copy to `config/config.json`.
   - Use the command-line interface to manage environments. The general usage is:
     ```sh
     python main.py env --type <EnvironmentType> <command> [options]
     ```
     - Replace `<EnvironmentType>` with the name of the environment class (e.g., `Dumbbell`, `Ring`, etc.).
     - `<command>` can be one of:
       - `setup`: Sets up the environment by deploying the network topology and configuring hosts. You can use `--skip_network` to skip network setup if already done.
       - `compile`: Fully deploys and configures the environment, including network and host provisioning, vulnerability injection, and data generation. Use `--skip_network` or `--skip_host` to skip parts of the process.
       - `teardown`: Tears down and cleans up the deployed environment, removing all resources from OpenStack.
       - `deploy_network`: Only deploys the network topology, without configuring hosts or running further setup.
     - Example:  
       ```sh
       python main.py env --type Dumbbell setup
       ```
     - For more options and help, run:
       ```sh
       python main.py env --help
       ```

## Customization

- **Topologies:** Modify or create new Python classes in `environment/specifications/` to define custom network layouts.
- **Vulnerabilities:** Add new Ansible roles or scripts in `ansible/vulnerabilities/`.
- **Data:** Adjust data generation logic in environment specifications for custom datasets.

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

MHBench leverages open-source tools including OpenStack, Terraform, and Ansible.