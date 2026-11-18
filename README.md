# MHBench: A system for generating multi-host environments for evaluating autonomous network attackers and defenders

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
![GitHub issues](https://img.shields.io/github/issues/bsinger98/MHBench?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/bsinger98/MHBench?style=flat-square)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/bsinger98/MHBench?style=flat-square)
![GitHub contributors](https://img.shields.io/github/contributors/bsinger98/MHBench?style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/bsinger98/MHBench?style=flat-square)
![GitHub forks](https://img.shields.io/github/forks/bsinger98/MHBench?style=flat-square)

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

## Scenario input (new, authoring/validation stage)

The existing MHBench deployment CLI takes `--type` as either a built-in
environment class or a generated **NetworkTopology JSON** file. That model
describes hosts, subnets, users, vulnerabilities, goals, and attack paths; it
does not currently define business departments, workflows, or concrete
container service builds.

The new backend-neutral input has two YAML documents, documented by the schemas
in `src/scenario/spec.py`:

1. `scenario.yaml` describes the business context: departments, actors,
   systems, and normal workflows. It does not select vulnerabilities.
2. `range-plan.yaml` realizes that scenario with concrete service references,
   the agent's explicit `entry_state` and separate Harbor `main` environment,
   network placement, service flows,
   capability-transition hypotheses, and resource goals. It can also carry
   `weakness_candidates` (sourced leads not
   yet selected or deployed) separately from `weaknesses` (selected instances
   that must resolve to deployable templates and explicitly name their
   `candidate_id`. The compiler does not randomly choose from the candidate
   pool; selection is an explicit, reviewed input.

An illustrative pair is in `examples/scenarios/east-quay-terminal/`. Validate
both together with:

```bash
uv run python -m src.scenario.validate \
  examples/scenarios/east-quay-terminal/scenario.yaml \
  examples/scenarios/east-quay-terminal/range-plan.yaml
```

Validation checks schema, references, selection evidence gates, and any
approved ordered capability chain; it does not resolve or build weakness
catalog entries. The East Quay YAML remains independent of the existing
OpenStack `--type` JSON deployment path. Its current service catalog resolves
to a Harbor-compatible Compose
environment; it records one **rejected** NanoMQ lead, no approved candidate
path, and zero selected/deployed weaknesses. Vulnerability selection remains
explicit; rendering requires a matching reviewed weakness catalog whenever
weaknesses are selected and fails rather than silently dropping them.

### Compose backend prototype

A separate Compose renderer now resolves `RangePlan.services[].catalog_ref`
against a service catalog, emits the Harbor `environment/Dockerfile` for the
unprivileged `main` agent, and writes a `docker-compose.yaml` overlay with
target services, networks, healthchecks, and copied build contexts. Harbor
provides the base `main` service; the task overlay adds its task-local network
attachments and security settings without replacing Harbor's built image.
An explicit `--weakness-catalog` can add reviewed file overlays to build-backed
services; it does not select candidates or support arbitrary deployment
scripts.

```bash
uv run python -m src.scenario.render_compose \
  --scenario examples/compose-smoke/scenario.yaml \
  --range-plan examples/compose-smoke/range-plan.yaml \
  --catalog examples/compose-smoke/service-catalog.yaml \
  --catalog-root examples/compose-smoke \
  --output /tmp/mhbench-compose-smoke

docker compose --project-directory /tmp/mhbench-compose-smoke \
  -f examples/compose-smoke/harness-compose.yaml \
  -f /tmp/mhbench-compose-smoke/docker-compose.yaml config --quiet
```

`examples/compose-smoke/` is only a renderer smoke fixture, not a benchmark
scenario. For the actual East Quay stack, run:

```bash
./examples/scenarios/east-quay-terminal/smoke.sh
```

The integration smoke uses the installed Harbor Compose build base when
available. It verifies that `main` can reach the port app and MQTT edge broker,
cannot reach the database, dispatch bridge, or controller, has no public
egress, and runs without added Linux capabilities. It also exercises
carrier/staff login, the clearance hold, the dispatch bridge, NanoMQ HTTP
authentication/ACL, and the controller's independently written MQTT event
plus database state.

### Harbor task compiler

MHBench also compiles the generated environment together with reviewed Harbor
task assets. It emits the entry-only `instruction.md` from `range-plan.yaml`,
copies the authored README/tests/solution assets, and writes
`environment/Dockerfile`, `environment/docker-compose.yaml`, and target build
contexts:

```bash
uv run python -m src.scenario.render_harbor_task \
  --scenario examples/scenarios/east-quay-terminal/scenario.yaml \
  --range-plan examples/scenarios/east-quay-terminal/range-plan.yaml \
  --catalog examples/scenarios/east-quay-terminal/service-catalog.yaml \
  --catalog-root examples/scenarios/east-quay-terminal \
  --task-assets examples/scenarios/east-quay-terminal/harbor-assets \
  --output /tmp/east-quay-terminal-task

harbor lint /tmp/east-quay-terminal-task
```

The checked-in East Quay task package was run with Harbor 0.25.0 and its
separate verifier Dockerfile. Harbor collected the controller-side event file
and a post-agent DB snapshot from their target sidecars, then passed those
artifacts to the separate test environment. A no-op Oracle trial scored 0.0,
as expected, confirming that the verifier does not award credit from an
agent-reported result.

This is still an **integration-preview task**, not a release-ready benchmark:
the vulnerable chain has no selected nodes yet. Candidate 407 (NanoMQ v5
topic-alias / HTTP ACL) is retained as rejected evidence only. Source
inspection of 0.25.6 shows empty-topic ACL parsing returns `NOT_AUTHORIZED`
before alias resolution; the public fix commit describes a false rejection,
not unauthorized command delivery. NanoMQ remains in the business topology as
the real MQTT message boundary, but no security credit is assigned to that
candidate.

Candidate 407 (NanoMQ v5 topic-alias / HTTP ACL) is retained as rejected
evidence only. Source inspection of the 0.25.6 tag shows empty-topic ACL
parsing returns `NOT_AUTHORIZED` before alias resolution; the public fix
commit's regression test describes false rejection, not unauthorized command
delivery. The candidate ledger and East Quay plan record the audit. NanoMQ
remains in the business topology as the real MQTT message boundary, but no
security credit is assigned to that candidate.

## Tips

- Ensure your SSH key referenced in `openstack_config.ssh_key_path` exists and
  is registered in OpenStack.
- Snapshots are automatically managed during `compile`; use `setup` to restore
  from existing snapshots without rebuilding everything.
