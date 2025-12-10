# MHBench: A system for generating multi-host environments for evaluating autonomous network attackers and defenders

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![GitHub issues](https://img.shields.io/github/issues/bsinger98/Incalmo?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/bsinger98/Incalmo?style=flat-square)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/bsinger98/Incalmo?style=flat-square)
![GitHub contributors](https://img.shields.io/github/contributors/bsinger98/Incalmo?style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/bsinger98/Incalmo?style=flat-square)
![GitHub forks](https://img.shields.io/github/forks/bsinger98/Incalmo?style=flat-square)

</div>

MHBench is a system for generating multi-host environments to evaluate autonomous attackers against autonomous defenders.
MHBench has 10 manually tuned environments based on real-world reports and 30 programmatically generated environments.

**Research Papers**:

[On the Feasibility of Using LLMs to Execute Multistage Network Attacks](https://arxiv.org/abs/2501.16466)

[Perry: A High-level Framework for Accelerating Cyber Deception Experimentation](https://arxiv.org/pdf/2506.20770)

## Requirements

- OpenStack project with API access and the ability to create networks, routers,
  floating IPs, and compute instances.
- Hardware requirements for local Openstack cluster: 64 vCPUs, 128 GB RAM, ~2 TB SSD.
- Python 3.13+ and [uv](https://docs.astral.sh/uv/) for dependency management.

## Setup

1) Install dependencies
   ```bash
   uv sync
   ```
2) Create a config file
   ```bash
   cp config/config_example.json config/config.json
   ```
   Fill in your OpenStack credentials (`openstack_config`), external IP, and any
   Elastic/C2 settings you use. The `openstack_setup/` directory contains helper
   scripts for bootstrapping DevStack or Kolla if you need an OpenStack node.

## Available environments

Pass one of these values to `--type`:
`EquifaxLarge`, `EquifaxMedium`, `EquifaxSmall`, `ICSEnvironment`, `ChainEnvironment`,
`PEChainEnvironment`, `Star`, `StarPE`, `Dumbbell`, `DumbbellPE`, `EnterpriseA`,
`EnterpriseB`, `Chain2Hosts`, `DevEnvironment`, `DevPrivTestEnvironment`.

## Usage

- Compile a topology: setup VMs, install dependencies, and save images.
  ```bash
  uv run python main.py --type EquifaxSmall compile
  ```
  Add `--skip_network` if you already built the network.

- Tear down all resources created by the range:
  ```bash
  uv run python main.py --type EquifaxSmall teardown
  ```

Run logs, Ansible artifacts, and Terraform outputs are stored under
`./output/misc/<timestamp>/`.

## Tips

- Ensure your SSH key referenced in `openstack_config.ssh_key_path` exists and
  is registered in OpenStack.
- Snapshots are automatically managed during `compile`; use `setup` to restore
  from existing snapshots without rebuilding everything.

