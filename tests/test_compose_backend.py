import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from click.testing import CliRunner
from src.scenario.compose_backend import (
    ServiceCatalog,
    ServiceTemplate,
    WeaknessCatalog,
    WeaknessTemplate,
    FileOverlay,
    load_bundle,
    load_yaml,
    render_compose,
)
from src.scenario.render_harbor_task import main as render_harbor_task
from src.scenario.validate import main as validate_scenario
from src.scenario.spec import (
    RangePlan,
    ScenarioBundle,
    ScenarioPlan,
    WeaknessCandidate,
    WeaknessInstance,
)
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "examples/scenarios/east-quay-terminal"
SMOKE_DIR = ROOT / "examples/compose-smoke"


class ScenarioSemanticValidationTest(unittest.TestCase):
    def _east_quay_bundle(self, scenario_raw=None):
        scenario_raw = scenario_raw or load_yaml(SCENARIO_DIR / "scenario.yaml")
        return ScenarioBundle(
            scenario=ScenarioPlan.model_validate(scenario_raw),
            range=RangePlan.model_validate(
                load_yaml(SCENARIO_DIR / "range-plan.yaml")
            ),
        )

    def test_scenario_plan_rejects_duplicate_semantic_ids(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["actors"][1]["id"] = scenario["actors"][0]["id"]
        with self.assertRaisesRegex(ValidationError, "duplicate actor id"):
            ScenarioPlan.model_validate(scenario)

    def test_workflow_actor_department_must_match_participating_systems(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["actors"][1]["department_id"] = "automation-engineering"
        with self.assertRaisesRegex(
            ValidationError,
            "workflow carrier-request-review includes actor cargo-clerk",
        ):
            self._east_quay_bundle(scenario)

    def test_business_system_must_be_grounded_in_a_workflow(self):
        scenario = load_yaml(SCENARIO_DIR / "scenario.yaml")
        scenario["systems"].append(
            {
                "id": "unrelated-it",
                "name": "Unrelated IT System",
                "purpose": "An unreferenced system with no stated business workflow.",
                "department_ids": ["terminal-operations"],
            }
        )
        with self.assertRaisesRegex(
            ValidationError,
            "business systems must participate in at least one workflow",
        ):
            self._east_quay_bundle(scenario)

    def test_validator_reports_selection_band_separately_from_triage_state(self):
        result = CliRunner().invoke(
            validate_scenario,
            [
                str(SCENARIO_DIR / "scenario.yaml"),
                str(SCENARIO_DIR / "range-plan.yaml"),
            ],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("core=1", result.output)
        self.assertIn("adjacent=2", result.output)
        self.assertIn("triage: candidate=2, rejected=2", result.output)


@unittest.skipUnless(shutil.which("docker"), "Docker CLI is not installed")
class ComposeBackendTest(unittest.TestCase):
    def _cve_candidate(self):
        families = [
            "cve_org_record",
            "nvd_record",
            "vendor_advisory",
            "github",
            "gitlab",
            "exploit_db",
            "packet_storm",
            "metasploit",
            "nuclei",
            "web_search",
        ]
        scopes = ["identifier", "product_version", "sink", "root_cause"]
        source_urls = {
            "cve_org_record": "https://www.cve.org/CVERecord?id=CVE-2099-1234",
            "nvd_record": "https://nvd.nist.gov/vuln/detail/CVE-2099-1234",
            "vendor_advisory": "https://vendor.example.com/security/CVE-2099-1234",
            "github": "https://github.com/search?q=CVE-2099-1234",
            "gitlab": "https://gitlab.com/search?search=CVE-2099-1234",
            "exploit_db": "https://www.exploit-db.com/search?cve=CVE-2099-1234",
            "packet_storm": "https://packetstormsecurity.com/search/?q=CVE-2099-1234",
            "metasploit": "https://github.com/rapid7/metasploit-framework/search?q=CVE-2099-1234",
            "nuclei": "https://github.com/projectdiscovery/nuclei-templates/search?q=CVE-2099-1234",
            "web_search": "https://www.google.com/search?q=CVE-2099-1234",
        }
        return {
            "id": "cve-screen-fixture",
            "source_track": "cve_no_public_poc",
            "source_ref": "test://CVE-2099-1234",
            "product": "test product",
            "vulnerable_baseline": "1.0",
            "fix_commit": "fixed-control",
            "cve_id": "CVE-2099-1234",
            "mechanism": "test only",
            "precondition": "test precondition",
            "requires_capabilities": ["test:entry"],
            "grants_capabilities": ["test:resource"],
            "resource_effects": ["test:resource"],
            "business_fit": "Schema fixture only.",
            "selection_band": "core",
            "selection_rationale": "Schema fixture only.",
            "public_poc_screen": "pass",
            "poc_searches": [
                {
                    "source_family": family,
                    "query_scope": scopes[index % len(scopes)],
                    "checked_on": "2026-11-18",
                    "query": f"CVE-2099-1234 test-product version 1.0 query {index}",
                    "url": source_urls[family],
                    "classification": "not_found",
                    "notes": "Test fixture; not research evidence.",
                }
                for index, family in enumerate(families)
            ],
        }

    def test_cve_candidate_requires_multisource_poc_search_evidence(self):
        raw = self._cve_candidate()
        raw["poc_searches"] = raw["poc_searches"][:-1]
        with self.assertRaisesRegex(ValidationError, "missing source families"):
            WeaknessCandidate.model_validate(raw)

    def test_cve_candidate_cannot_pass_with_exact_public_reproducer(self):
        raw = self._cve_candidate()
        raw["poc_searches"][0]["classification"] = "exact"
        with self.assertRaisesRegex(ValidationError, "exact public PoC"):
            WeaknessCandidate.model_validate(raw)

    def test_cve_candidate_requires_fallback_for_unavailable_search_surface(self):
        raw = self._cve_candidate()
        gitlab_record = next(
            record
            for record in raw["poc_searches"]
            if record["source_family"] == "gitlab"
        )
        gitlab_record["classification"] = "unavailable"
        with self.assertRaisesRegex(ValidationError, "domain-restricted web-search"):
            WeaknessCandidate.model_validate(raw)

        web_record = next(
            record
            for record in raw["poc_searches"]
            if record["source_family"] == "web_search"
        )
        web_record["fallback_for"] = ["gitlab"]
        web_record["query"] = (
            "site:gitlab.com CVE-2099-1234 test-product version 1.0"
        )
        candidate = WeaknessCandidate.model_validate(raw)
        self.assertEqual(candidate.id, "cve-screen-fixture")

    def test_cve_search_record_rejects_wrong_domain_and_future_date(self):
        wrong_domain = self._cve_candidate()
        wrong_domain["poc_searches"][0]["url"] = "https://example.com/search"
        with self.assertRaisesRegex(ValidationError, "must be hosted on cve.org"):
            WeaknessCandidate.model_validate(wrong_domain)

        future_date = self._cve_candidate()
        future_date["poc_searches"][0]["checked_on"] = "2099-01-01"
        with self.assertRaisesRegex(ValidationError, "cannot be in the future"):
            WeaknessCandidate.model_validate(future_date)

    def _three_node_plan(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["weakness_candidates"] = []
        raw["weaknesses"] = []
        raw["attack_transitions"] = []
        raw["candidate_paths"] = []
        raw["goals"][0]["target_capabilities"] = ["integrity:target-record"]
        hops = (
            ("http:get_status", "credential:internal-worker"),
            ("credential:internal-worker", "session:maintenance-access"),
            ("session:maintenance-access", "integrity:target-record"),
        )
        for index, (required, granted) in enumerate(
            hops,
            start=1,
        ):
            candidate_id = f"candidate-{index}"
            is_primary = index == 3
            raw["weakness_candidates"].append(
                {
                    "id": candidate_id,
                    "source_track": "deployed_weakness",
                    "source_ref": f"test://candidate-{index}",
                    "product": "smoke fixture",
                    "vulnerable_baseline": "1.0",
                    "corrected_control_ref": f"control://fixed-{index}",
                    "mechanism": f"verified mechanism {index}",
                    "precondition": required,
                    "requires_capabilities": [required],
                    "grants_capabilities": [granted],
                    "resource_effects": [granted],
                    "business_fit": "Used only to exercise ordered path validation.",
                    "selection_band": "core",
                    "selection_rationale": "Test fixture.",
                    "triage_status": "selected",
                    "artifact_pair_status": "deployment-control-pair",
                    "public_poc_screen": "not_applicable",
                    "live_reproduction": "pass",
                    "case_role": "primary" if is_primary else "chain_tissue",
                    "knowledge_thresholds": {
                        "k1": {
                            "result": "not_crossed",
                            "evidence": "The test fixture identifies the HTTP service.",
                        },
                        "k2": {
                            "result": "not_crossed",
                            "evidence": "No product-specific defect discovery is modeled in this fixture.",
                        },
                        "k3": {
                            "result": "crossed" if is_primary else "not_crossed",
                            "evidence": (
                                "The final fixture hop requires constructing a protocol message."
                                if is_primary
                                else "The fixture hop uses a simple request."
                            ),
                        },
                    },
                    "enumeration": {
                        "status": "acceptable",
                        "surface": "Smoke fixture capability transition",
                        "authentication_state": "test-only",
                        "input_fields": ["test payload"],
                        "minimum_search_space": 16 if is_primary else 1,
                        "interaction_rounds": 3 if is_primary else 1,
                        "protocol_construction_required": is_primary,
                        "rationale": (
                            "The final hop requires a structured wire message."
                            if is_primary
                            else "Included only as chain tissue in this schema fixture."
                        ),
                    },
                }
            )
            raw["weaknesses"].append(
                {
                    "id": f"weakness-{index}",
                    "candidate_id": candidate_id,
                    "service_id": "status-page",
                    "catalog_ref": f"weakness://smoke/{index}",
                    "rationale": "Test fixture.",
                }
            )
            raw["attack_transitions"].append(
                {
                    "id": f"transition-{index}",
                    "from_capability": required,
                    "to_capability": granted,
                    "weakness_id": f"weakness-{index}",
                }
            )
        raw["candidate_paths"] = [
            {
                "id": "approved-three-node-chain",
                "candidate_ids": ["candidate-1", "candidate-2", "candidate-3"],
                "target_goal_id": "read-status",
                "target_capability": "integrity:target-record",
                "primary_candidate_id": "candidate-3",
                "rationale": "A connected three-node test chain.",
                "status": "approved",
            }
        ]
        return raw

    def test_approved_candidate_path_validates_as_ordered_capability_chain(self):
        plan = RangePlan.model_validate(self._three_node_plan())
        self.assertEqual(plan.candidate_paths[0].status, "approved")

    def test_selected_weakness_rejects_unselected_candidate(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][0]["triage_status"] = "candidate"
        with self.assertRaisesRegex(ValidationError, "triage_status"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_rejects_disconnected_order(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["candidate_ids"] = [
            "candidate-3",
            "candidate-1",
            "candidate-2",
        ]
        with self.assertRaisesRegex(ValidationError, "continuous chain"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_requires_three_or_more_nodes(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["candidate_ids"] = [
            "candidate-1",
            "candidate-2",
        ]
        raw["candidate_paths"][0]["primary_candidate_id"] = "candidate-2"
        with self.assertRaisesRegex(ValidationError, "at least three vulnerability nodes"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_requires_protocol_cost(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][2]["knowledge_thresholds"]["k3"] = {
            "result": "not_crossed",
            "evidence": "No protocol construction in this negative test.",
        }
        with self.assertRaisesRegex(
            ValidationError, "must pass the enumeration screen"
        ):
            RangePlan.model_validate(raw)

    def test_primary_candidate_cannot_pass_with_small_enumeration(self):
        raw = self._three_node_plan()
        raw["weakness_candidates"][2]["enumeration"]["status"] = "too_small"
        raw["weakness_candidates"][2]["enumeration"]["minimum_search_space"] = 3
        with self.assertRaisesRegex(ValidationError, "enumeration screen"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_must_reach_resource_goal_capability(self):
        raw = self._three_node_plan()
        raw["candidate_paths"][0]["target_capability"] = "integrity:other-record"
        with self.assertRaisesRegex(ValidationError, "not declared by resource goal"):
            RangePlan.model_validate(raw)

    def test_selected_weakness_requires_reviewed_weakness_catalog(self):
        bundle = load_bundle(
            SCENARIO_DIR / "scenario.yaml",
            SCENARIO_DIR / "range-plan.yaml",
        )
        bundle = bundle.model_copy(
            update={
                "range": bundle.range.model_copy(
                    update={
                        "weaknesses": [
                            WeaknessInstance(
                                id="selected-unimplemented",
                                candidate_id="source-candidate-not-present",
                                service_id="declaration-portal",
                                catalog_ref="weakness://missing/template",
                                rationale="negative test",
                            )
                        ]
                    }
                )
            }
        )
        catalog = ServiceCatalog(
            schema_version="1.0",
            services=[
                ServiceTemplate(
                    catalog_ref="unused",
                    delivery="image",
                    image="busybox:1.36",
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "requires a reviewed weakness catalog"):
                render_compose(bundle, catalog, Path(temp), Path(temp) / "out")

    def test_selected_weaknesses_render_reviewed_file_overlays(self):
        raw_bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        )
        plan = RangePlan.model_validate(self._three_node_plan())
        bundle = raw_bundle.model_copy(update={"range": plan})
        catalog = ServiceCatalog.model_validate(
            load_yaml(SMOKE_DIR / "service-catalog.yaml")
        )
        weakness_catalog = WeaknessCatalog(
            schema_version="1.0",
            weaknesses=[
                WeaknessTemplate(
                    catalog_ref=f"weakness://smoke/{index}",
                    candidate_ids=[f"candidate-{index}"],
                    service_catalog_ref="service://smoke/http",
                    file_overlays=[
                        FileOverlay(
                            source=f"weakness-overlays/node-{index}.txt",
                            target=f"/usr/share/nginx/html/node-{index}.txt",
                        )
                    ],
                )
                for index in (1, 2, 3)
            ],
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "catalog"
            shutil.copytree(SMOKE_DIR / "build", root / "build")
            (root / "weakness-overlays").mkdir()
            for index in (1, 2, 3):
                (root / "weakness-overlays" / f"node-{index}.txt").write_text(
                    f"selected weakness overlay {index}\n"
                )
            output = Path(temp) / "rendered" / "environment"
            compose_file = render_compose(
                bundle,
                catalog,
                catalog_root=root,
                output_dir=output,
                weakness_catalog=weakness_catalog,
            )
            service = yaml.safe_load(compose_file.read_text())["services"][
                "status-page"
            ]
            project_name = f"mhbench-overlay-{Path(temp).name}"
            compose_args = [
                "docker",
                "compose",
                "--project-name",
                project_name,
                "--project-directory",
                str(output),
                "-f",
                str(SMOKE_DIR / "harness-compose.yaml"),
                "-f",
                str(compose_file),
            ]
            self.assertEqual(
                service["build"]["dockerfile"], "Dockerfile.mhbench"
            )
            dockerfile = (
                output / "build/status-page/Dockerfile.mhbench"
            ).read_text()
            self.assertIn("/usr/share/nginx/html/node-1.txt", dockerfile)
            self.assertIn("/usr/share/nginx/html/node-2.txt", dockerfile)
            self.assertEqual(
                len(list((output / "build/status-page/_mhbench/weaknesses").glob("*/*"))),
                3,
            )
            subprocess.run(
                [*compose_args, "build", "status-page"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    *compose_args,
                    "run",
                    "--rm",
                    "--no-deps",
                    "status-page",
                    "sh",
                    "-c",
                    (
                        "test \"$(cat /usr/share/nginx/html/node-1.txt)\" "
                        "= 'selected weakness overlay 1' && "
                        "test \"$(cat /usr/share/nginx/html/node-2.txt)\" "
                        "= 'selected weakness overlay 2'"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_selected_weakness_must_reference_a_listed_candidate(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["weaknesses"] = [
            {
                "id": "selected-1",
                "candidate_id": "not-in-candidate-pool",
                "service_id": "status-page",
                "catalog_ref": "weakness://smoke/example",
                "rationale": "negative validation case",
            }
        ]
        with self.assertRaisesRegex(ValidationError, "unknown weakness candidate"):
            RangePlan.model_validate(raw)

    def test_rendered_compose_is_valid_and_copies_build_context(self):
        bundle = load_bundle(
            SMOKE_DIR / "scenario.yaml",
            SMOKE_DIR / "range-plan.yaml",
        )
        catalog = ServiceCatalog.model_validate(
            load_yaml(SMOKE_DIR / "service-catalog.yaml")
        )
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "task" / "environment"
            compose_file = render_compose(bundle, catalog, SMOKE_DIR, output)
            self.assertTrue((output / "build/status-page/Dockerfile").is_file())
            self.assertTrue((output / "build/status-page/index.html").is_file())
            self.assertTrue((output / "Dockerfile").is_file())
            compose = yaml.safe_load(compose_file.read_text())
            self.assertEqual(compose["services"]["main"]["networks"], ["agent-edge"])
            self.assertEqual(compose["services"]["main"]["cap_drop"], ["ALL"])
            self.assertNotIn("build", compose["services"]["main"])
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(SMOKE_DIR / "harness-compose.yaml"),
                    "-f",
                    str(compose_file),
                    "config",
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_east_quay_renders_isolated_harbor_main_and_real_service_builds(self):
        bundle = load_bundle(
            SCENARIO_DIR / "scenario.yaml",
            SCENARIO_DIR / "range-plan.yaml",
        )
        catalog = ServiceCatalog.model_validate(
            load_yaml(SCENARIO_DIR / "service-catalog.yaml")
        )
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "environment"
            compose_file = render_compose(bundle, catalog, SCENARIO_DIR, output)
            compose = yaml.safe_load(compose_file.read_text())
            self.assertTrue((output / "Dockerfile").is_file())
            for service in (
                "port-app",
                "port-db",
                "yard-dispatch",
                "yard-control",
                "yard-broker",
            ):
                self.assertTrue((output / f"build/{service}/Dockerfile").is_file())
            main = compose["services"]["main"]
            self.assertEqual(main["networks"], ["agent-edge"])
            self.assertEqual(main["cap_drop"], ["ALL"])
            self.assertEqual(main["security_opt"], ["no-new-privileges:true"])
            self.assertNotIn("ports", main)
            self.assertTrue(compose["networks"]["agent-edge"]["internal"])
            self.assertEqual(
                compose["services"]["port-db"]["networks"], ["operations"]
            )
            self.assertEqual(
                compose["services"]["yard-control"]["networks"],
                ["operations", "ot-segment"],
            )
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "--project-directory",
                    str(output),
                    "-f",
                    str(SCENARIO_DIR / "harness-compose.yaml"),
                    "-f",
                    str(compose_file),
                    "config",
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_harbor_task_compiler_keeps_instruction_entry_only(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "east-quay-task"
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(SCENARIO_DIR / "scenario.yaml"),
                    "--range-plan",
                    str(SCENARIO_DIR / "range-plan.yaml"),
                    "--catalog",
                    str(SCENARIO_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(SCENARIO_DIR),
                    "--task-assets",
                    str(SCENARIO_DIR / "harbor-assets"),
                    "--output",
                    str(output),
                ],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue((output / "environment/Dockerfile").is_file())
            self.assertTrue((output / "environment/docker-compose.yaml").is_file())
            self.assertTrue((output / "tests/Dockerfile").is_file())
            self.assertTrue((output / "tests/test_outputs.py").is_file())
            instruction = (output / "instruction.md").read_text()
            self.assertIn("http://port-app/", instruction)
            self.assertIn("agent@northshore.example", instruction)
            self.assertNotIn("loaded", instruction.lower())
            self.assertNotIn("clearance", instruction.lower())

    def test_harbor_task_compiler_deploys_explicit_weakness_catalog(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "catalog"
            shutil.copytree(SMOKE_DIR / "build", root / "build")
            (root / "weakness-overlays").mkdir()
            (root / "weakness-overlays" / "proof.txt").write_text("overlay\n")
            range_file = Path(temp) / "range-plan.yaml"
            range_file.write_text(yaml.safe_dump(self._three_node_plan()))
            weakness_catalog_file = Path(temp) / "weaknesses.yaml"
            weakness_catalog_file.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": "1.0",
                        "weaknesses": [
                            {
                                "catalog_ref": f"weakness://smoke/{index}",
                                "candidate_ids": [f"candidate-{index}"],
                                "service_catalog_ref": "service://smoke/http",
                                "file_overlays": [
                                    {
                                        "source": "weakness-overlays/proof.txt",
                                        "target": f"/usr/share/nginx/html/proof-{index}.txt",
                                    }
                                ],
                            }
            for index in (1, 2, 3)
                        ],
                    }
                )
            )
            assets = Path(temp) / "assets"
            assets.mkdir()
            (assets / "task.toml").write_text('[task]\nname="smoke"\n')
            (assets / "README.md").write_text("# Smoke task\n")
            output = Path(temp) / "task"
            result = CliRunner().invoke(
                render_harbor_task,
                [
                    "--scenario",
                    str(SMOKE_DIR / "scenario.yaml"),
                    "--range-plan",
                    str(range_file),
                    "--catalog",
                    str(SMOKE_DIR / "service-catalog.yaml"),
                    "--catalog-root",
                    str(root),
                    "--weakness-catalog",
                    str(weakness_catalog_file),
                    "--task-assets",
                    str(assets),
                    "--output",
                    str(output),
                ],
            )
            self.assertEqual(result.exit_code, 0, result.output)
            generated_dockerfile = (
                output / "environment/build/status-page/Dockerfile.mhbench"
            )
            self.assertTrue(generated_dockerfile.is_file())
            self.assertIn(
                "/usr/share/nginx/html/proof-1.txt",
                generated_dockerfile.read_text(),
            )


if __name__ == "__main__":
    unittest.main()
