# Harbor task compiler: design proposal

**Status:** implementation preview. The scenario/range schemas, Compose
renderer, Harbor task compiler, and East Quay integration fixture are
implemented. A deployable weakness catalog/adapter is still missing, so
East Quay has no selected weakness instances yet. A reviewed file-overlay
adapter exists for build-backed services, but no East Quay weakness templates
have passed the candidate research and live-reproduction gates.

The first executable part of this proposal is a two-stage, backend-neutral
input contract in `src/scenario/spec.py`: the business scenario at
`examples/scenarios/east-quay-terminal/scenario.yaml` and its concrete range
realization at `examples/scenarios/east-quay-terminal/range-plan.yaml`.
Validate the pair with:

```bash
uv run python -m src.scenario.validate \
  examples/scenarios/east-quay-terminal/scenario.yaml \
  examples/scenarios/east-quay-terminal/range-plan.yaml
```

This command validates schema and cross-references; it does not yet resolve
weakness catalog entries. The East Quay range plan carries a
`weakness_candidates` list distinct from `weaknesses`:
candidates are research leads, while weakness instances are selected,
deployable entries. Deploying one requires a selected candidate, a passed
public-PoC screen, live vulnerable/fixed reproduction, and a verified artifact
pair. Candidates identify their source track: CVE with no public PoC, silent
upstream fix, or deployed weakness. A CVE candidate cannot pass the PoC gate
without dated per-source query records covering CVE.org, NVD, vendor advisory,
GitHub, GitLab, Exploit-DB, Packet Storm, Metasploit, Nuclei, and general web
search, plus identifier, product/version, sink, and root-cause query scopes.
Any exact public reproducer makes a passing CVE screen invalid. An unavailable
search surface must be paired with a domain-restricted web-search fallback.
Search URLs must match the declared source family, and future-dated checks
are rejected. Approved candidate paths must list explicitly deployed
candidates in
capability-contiguous order and name a target capability declared by the
linked resource goal. These checks stop an unreviewed or disconnected path
from being represented as approved; they do not discover the path or deploy
its weaknesses.

Each candidate also carries K1/K2/K3 assessments and a static enumeration
estimate. K1 is stack identification, K2 is defect-specific knowledge, and K3
is constructing the required protocol message. A selected primary candidate
must have at least one evidenced threshold and pass the enumeration screen.
An approved case hypothesis requires at least three selected nodes, an
explicit primary candidate, and at least one K3-crossing node. Lower-cost
nodes may be labeled chain tissue, but they cannot make an otherwise
enumeration-shaped weakness count as the primary case.

A first Compose adapter is available at `src/scenario/compose_backend.py`.
It resolves service `catalog_ref`s against a reviewed service catalog,
renders Compose and copies declared build contexts. The first weakness adapter
supports explicit file overlays on build-backed services. Each selected
weakness must resolve through a separate catalog entry whose candidate and
service compatibility are checked; duplicate target paths and missing overlay
files fail closed. This is an adapter primitive, not yet a populated library
of validated East Quay vulnerabilities. The smoke fixture lives in
`examples/compose-smoke/`. The renderer plus Harbor task compiler has been
exercised with Docker Compose and Harbor 0.25.0. This proves local integration
only, not yet stock-Harbor portability across other Harbor versions.

## Recommendation

Do not make an LLM a runtime dependency of the environment generator, and do
not replace MHBench's OpenStack deployment path with Harbor-specific logic.

Treat MHBench as a source of useful ideas—typed topology specifications,
host/identity and vulnerability models, attack-path graphs, reproducible seeds,
and compilation from declarative input—but do not mistake those for scenario
semantics. Build Harbor task generation as a separate compiler package/backend.
If the long-term goal is one project that supports both VM cyber ranges and
Harbor tasks, share a backend-neutral scenario specification and keep
OpenStack/GCP and Docker/Harbor as independent deployment backends.

The generator must model two distinct things:

1. **Scenario semantics:** why the organization, departments, systems, data,
   and workflows exist, and how they depend on one another in normal operation.
2. **Cyber-range structure:** concrete services, identities, trust zones,
   network/data-flow edges, weaknesses, capability transitions, and goals.

Network reachability or an attack path alone does not establish that a range
is a coherent business system. Conversely, business prose alone does not
produce a runnable range. The compiler must preserve the traceable mapping
between the two.

The current `bsinger98/MHBench` checkout is VM/OpenStack-oriented:

- `src/models/network.py` describes networks, subnets, hosts, users,
  vulnerabilities, goals, and attack paths.
- `src/topology_generator/network_generator.py` generates generic host/subnet
  topologies, then selects vulnerability classes from a playbook catalog.
- `src/topology_generator/attack_path_generator.py` currently models lateral
  movement and privilege escalation, not web workflows, service identity,
  broker protocol, or Harbor resource scoring.
- `src/env_gen_deployer.py` provisions OpenStack networks/hosts, runs Ansible,
  and snapshots the VMs.

That is a useful infrastructure-level range generator, but not yet a
service-template catalog or Harbor-task builder. Replacing the backend in-place
would be a substantial redesign; adding a clean Harbor adapter is less likely
to break MHBench's current VM workflow.

### Attack-path behavior: what is and is not automated

MHBench's current path pipeline should not be described as attack-chain
discovery. The `AttackPath` is the plan: validation checks host/user
continuity, graph construction compiles declared steps into graph edges,
edge-pruning/merge logic handles duplicate vulnerability relationships, and
the vulnerability assigner selects deployment playbooks for those steps.
The topology generator can synthesize a naive path skeleton constrained by
subnet reachability, but that is still path construction under assumptions
(including an assumed foothold), not scanning real services and inferring
applicable vulnerabilities.

For the Harbor extension, use explicit, catalog-backed capability transitions
as **composition hypotheses**. A transition must point at a weakness template
whose preconditions and granted capability support that edge. The compiler
may validate and render that authored graph; it must not claim to discover the
graph from network links, randomly attach a weakness to make a path work, or
require the tested agent to follow the graph. Actual runtime evidence and
resource goals remain the scoring oracle.

## LLM: optional authoring aid, not part of compilation

There are two different questions: “Can the system generate a scenario?” and
“Must the environment compiler call an LLM?” The system can support
LLM-assisted generation of a complete **draft** scenario, but the compiler
should be deterministic and work without an LLM. Scenario semantics involve
creative choices (organization, actors, workflows, business records, and
system responsibilities), so an LLM can help draft those and propose mappings
to available services. This is an authoring interface, not a trusted source of
facts or a required runtime dependency. A human can also write the same
specification directly.

LLM output is an untrusted proposal:

1. Products and versions must resolve to an approved service catalog entry.
2. Vulnerability references must resolve to sourced and validated weakness
  records; the LLM must not invent CVEs, PoCs, or vulnerability claims.
3. The generated specification must pass schema, compatibility, provenance,
  workflow-consistency, and business-naturalness checks.
4. Unsupported service needs must be surfaced as gaps, not silently filled by
  invented “realistic” products or large amounts of bespoke glue.
5. A human approves the scenario/service/weakness mapping before packaging.

The deterministic compiler then renders Dockerfiles, environment orchestration,
Harbor metadata, and verifier skeletons from the approved specification.
LLM-based attackers belong in the later evaluation harness, not in environment
compilation.

## Where scenario generation belongs

Do not put business-story generation inside MHBench's topology randomizer or
attack-path generator. Add a separate **Scenario Authoring** layer that emits
the backend-neutral semantic specification above. Then compile that approved
specification through independent backend adapters:

```text
Human brief or optional LLM-assisted authoring
                  |
                  v
ScenarioPlan + workflow/system semantics
                  |
      catalog resolution + review
                  |
                  v
      validated CyberRangeSpec
             /           \
            v             v
 MHBench VM backend   Harbor backend
 existing OpenStack   Compose + per-service Dockerfiles
 backend retained     + Harbor task package
```

MHBench should contribute its existing network, identity, weakness, goal, and
attack-path abstractions where they fit, while the new semantic schema remains
the source for organizational purpose and business workflows. Keep this
boundary explicit: scenario authoring answers why the systems exist; backend
compilation answers how to deploy them. This allows a later VM range and a
Harbor task to derive from the same approved scenario without forcing either
backend's deployment assumptions into the other.

For the requested Harbor artifact, the Harbor adapter should emit a standard
`docker-compose.yaml`, a build context/Dockerfile for each service that needs
a custom image, and the Harbor task package. Prefer pinned upstream images
without a Dockerfile where appropriate; “a bunch of Dockerfiles” should mean
one per customized service, not gratuitous wrappers around every stock image.
The adapter must preserve network segmentation and service lifecycle behavior,
and produce portable output that works with stock Harbor rather than relying
on local absolute paths or an undocumented import hook.

Recommended implementation sequence:

1. Define and validate the semantic `ScenarioPlan`, then build reviewed
   service/weakness
   catalogs, including workflow-to-system traceability.
2. Build a deterministic validator/compiler CLI with a hand-authored fixture;
   retain MHBench's existing VM code path unchanged.
3. Complete weakness-catalog resolution and safe deployment adapters; only
   then allow non-empty weakness plans through the Compose renderer.
4. Package the generated environment as a Harbor task and verify it with a
   stock-Harbor smoke test.
5. Add optional LLM-assisted scenario drafting against the catalogs, with
   explicit unresolved-dependency reporting and human approval.
6. Only then consider using the same spec to generate MHBench VM ranges or
   broader automated scenario variants.

This ordering tests whether the semantic model and concrete service catalog
are expressive enough before introducing LLM variability. It also avoids
confusing “LLM produced plausible prose” with “the business scenario is
deployable, coherent, and scoreable.”

## Two-stage input model

The input is deliberately split into two authoring artifacts. Stage 1 captures
business semantics without committing to vulnerabilities or deployment
mechanics. Stage 2 maps that scenario to reviewed concrete services and
weaknesses, then defines the runtime topology and scoring evidence. Keep Harbor
packaging as a compiler projection, not more scenario prose.

```text
ScenarioPlan (stage 1)
  └── Departments
        └── Business systems
              └── Workflows, actors, and business records

RangePlan (stage 2, references ScenarioPlan)
  ├── EntryState: initial actor, entry service, authentication, capabilities
  └── Concrete service instances (catalog references)
        └── Weakness instances (evidence-backed references)

RangeTopology: service instances, trust zones, links, ports, normal data flow
AttackPathHypotheses: possible capability transitions for composition checks
ResourceGoals: resources/capabilities and trusted evidence used for scoring
HarborTaskSpec: task metadata, instruction scope, environment, tests, hints
```

Suggested input files for one scenario:

```text
scenario.yaml          # business context, actors, departments, purpose
workflows.yaml         # normal business processes, data/assets, system dependencies
systems.yaml           # business systems and their workflow responsibilities
range-plan.yaml        # service mappings, topology, weakness instances, goals
catalog/services/      # reviewed products, versions, image/build recipes
catalog/weaknesses/    # provenance, preconditions, capability effects, controls
```

The scenario-to-service relationship is many-to-many: a department need not
own a dedicated service, and a service may support several departments. Never
materialize one container per department by default.

Candidate preconditions and effects should use structured capability IDs as
well as explanatory prose. This permits deterministic checks against the
declared entry state and makes missing bridges visible. A candidate that is
thematically related but requires an identity or permission no prior step can
produce is not a valid chain node.

### Scenario semantics versus topology

The business model should answer “why is this system here?” before the range
model answers “which host/container runs it?” For example, a cargo declaration
workflow may connect an external agent portal, an operations application, and
an account/settlement system because each has a defined role in the workflow.
Those roles and dependencies should be explicit data, not inferred from
container links or invented after vulnerabilities are selected.

The model must distinguish at least:

- **Network relations:** who can connect to which service and on what port.
- **Security relations:** which identity or weakness can yield which capability.
- **Business relations:** which actor performs which workflow, which systems
  support it, and which business records/assets are created, consumed, or
  changed.

Generic products such as a web application, database, directory, or message
broker can implement parts of an industry scenario, but their presence alone
does not make the scenario realistic. Each selected service must have a
plausible operational role in a named business system and support a normal
workflow. Avoid both extremes: an arbitrary vulnerability playground, and an
industry-specific architecture that requires inventing many unavailable
products. Prefer a small number of real, reusable services plus minimal,
clearly bounded glue only where needed to connect business state or expose a
verifiable outcome.

Add validation rules for semantic coherence: every deployed service maps to a
business-system responsibility; every business-system dependency is reflected
in data flow or an explicit human/process interaction; and every scored
resource belongs to a business asset or capability with an explainable role.
These checks can flag missing rationale, but human review is still required to
judge whether the resulting organization and workflow feel plausible.

### Service catalog entry

Each reusable service template should identify:

- upstream project, exact version/tag, immutable image digest or reproducible
  Dockerfile source;
- normal business role and supported workflow;
- ports, dependencies, data volumes, health/readiness checks, user/process
  model, and network requirements;
- how to seed episode-specific state and how to reset it;
- Harbor packaging mode(s) supported;
- validated weakness IDs it can host and required companion services.

### Weakness entry

Each weakness template should identify:

- source track: CVE with no matching public PoC, silent upstream fix, or
  realistic deployed weakness (credentials, internal Git secret, trust/config);
- affected service/version/configuration and exact preconditions;
- public disclosure and PoC-search record where applicable;
- capability/resource obtained, not just the exploit action;
- affected and corrected control variants, benign/baseline controls, shortcut
  sweep, and server-observed verifier evidence;
- setup adapter (image overlay, configuration, seed data, or one-shot
  provisioning) with a declared merge/compatibility policy.

Do not randomly inject generic vulnerability playbooks into arbitrary hosts.
Only compose weaknesses whose service/version/precondition contracts match.

## Attack paths are hypotheses, not task instructions or score order

MHBench-style attack paths are useful during scenario construction to answer:

- Is every intended target resource reachable from the declared entry?
- Which services/weaknesses are shared by alternative paths?
- Are there accidental shortcuts or default credentials?
- Does each 3–5-node weakness chain have real capability transitions?

They must not be copied into the Agent instruction or treated as the required
score order. Harbor scoring remains resource/capability based and grants credit
for any path that produces trustworthy evidence of the resource. A path graph
is a composition/coverage aid; a ResourceGoal is the scoring contract.

## Candidate selection is evidence-driven, never random

Do not sample vulnerabilities randomly from the catalog to meet a target count.
The candidate pool is an explicitly sourced research list; selection for a
scenario proceeds through deterministic gates:

1. **Business fit:** the affected record/capability belongs to a named system
   and normal workflow in `ScenarioPlan`, with a clear operational owner.
2. **Version compatibility:** vulnerable baseline and fixed control are
   identifiable, reproducible, and compatible with the other selected nodes.
   Candidates requiring different vulnerable versions of the same product
   cannot be combined without a justified multi-instance design.
3. **Capability fit:** the weakness's real preconditions are reachable from
   the structured `entry_state` or a justified capability transition; each
   claimed transition must be supported by evidence, not by thematic similarity
   or network reachability alone.
4. **Impact and oracle:** the weakness can produce a meaningful protected
   resource/state change, with trusted evidence that distinguishes vulnerable
   from fixed and no-op behavior.
5. **Disclosure and safety screen:** record upstream disclosure status; for
   CVEs, perform the required multi-source exact-PoC search. Do not equate
   “no CVE” with “undisclosed” or “no public exploit.”
6. **Implementation feasibility:** prefer real catalog services and
   reproducible setup. Reject combinations that need excessive bespoke glue
   or cannot run in the claimed Harbor environment.

The East Quay `RangePlan` records a candidate pool, not a selected chain:
`selection_band` and `selection_rationale` make the initial business-fit
triage explicit, while `triage_status` keeps each item unapproved until
version/live/PoC checks are done. `core`, `adjacent`, `alternate`, and
`deferred` are review-order labels, not scores and not an instruction to
include a fixed number of nodes. Final selection requires the gates above and
human review; no random choice is used. The compiler consumes only explicit
`weaknesses` entries, each linked through `candidate_id` to a candidate and to
a deployable weakness catalog template. The candidate pool is never sampled
automatically.

`candidate_paths` can record a proposed composition over candidate IDs and
the gates still open for it. These are review hypotheses only: they do not
select or deploy weaknesses, define required attack order, or award score.

## Compiler outputs

For an approved spec, generate a Harbor task package and a reproducible
environment build:

```text
<task>/
  task.toml
  instruction.md
  environment/
    Dockerfile(s)
    docker-compose.yaml      # only when the selected Harbor environment mode permits it
    entrypoint/seed files
  tests/                     # verifier and reward logic
  solution/                  # oracle/reference implementation
  hint/hint.md               # optional, single hint
```

The Compose file and Dockerfiles are environment artifacts; `task.toml`,
instruction, hints, and verifier define the Harbor task. The compiler should
have explicit output modes instead of assuming every deployment topology maps
to the same package:

- **Harbor Compose mode:** emit standard Harbor `environment/docker-compose.yaml`
  plus per-service Dockerfiles/images.
- **Dockerfile-only mode:** emit one target image; reject or simplify
  topologies that require independent network/PID/filesystem boundaries rather
  than pretending one container provides them.
- **Developer smoke mode:** may add local-only conveniences, but must not leak
  paths, mounts, credentials, or scoring interfaces into the portable task.

The exact allowed task packaging mode must be selected before implementing the
backend. Do not silently depend on a custom `import_path`.

## Validation pipeline

Generation is not acceptance. The generated artifacts still have to pass:

1. schema and reference resolution;
2. reproducible image build and digest capture;
3. service readiness and normal-business positive controls;
4. each weakness's affected/corrected/benign/baseline controls;
5. shortcut and alternate-path sweeps;
6. trusted verifier evidence and anti-reward-hacking tests;
7. stock-Harbor smoke for the claimed portability mode;
8. oracle, no-op, hinted, and unhinted trials with trajectories.

The compiler can automate these checks, but it cannot certify an untested
service template or establish that a vulnerability chain is a natural business
composition.

## Suggested first vertical slice

Use the East Quay scenario only as the first integration test for the schema,
not as proof that every planned service is selected. Start with the most
implementation-supported cargo application candidate (Dolibarr + MariaDB),
then add an optional real broker only if the validated weakness chain and
normal shipment workflow need it. Keep any custom portal and yard-state process
small and explicit. Do not add OpenStack, a full multi-VM layer, or an LLM call
to the first compiler prototype.
