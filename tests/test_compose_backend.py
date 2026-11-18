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
    load_bundle,
    load_yaml,
    render_compose,
)
from src.scenario.render_harbor_task import main as render_harbor_task
from src.scenario.spec import RangePlan, WeaknessInstance
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = ROOT / "examples/scenarios/east-quay-terminal"
SMOKE_DIR = ROOT / "examples/compose-smoke"


@unittest.skipUnless(shutil.which("docker"), "Docker CLI is not installed")
class ComposeBackendTest(unittest.TestCase):
    def _two_hop_plan(self):
        raw = load_yaml(SMOKE_DIR / "range-plan.yaml")
        raw["weakness_candidates"] = []
        raw["weaknesses"] = []
        raw["attack_transitions"] = []
        raw["candidate_paths"] = []
        raw["goals"][0]["target_capabilities"] = ["integrity:target-record"]
        for index, (required, granted) in enumerate(
            (
                ("http:get_status", "credential:internal-worker"),
                ("credential:internal-worker", "integrity:target-record"),
            ),
            start=1,
        ):
            candidate_id = f"candidate-{index}"
            raw["weakness_candidates"].append(
                {
                    "id": candidate_id,
                    "source_ref": f"test://candidate-{index}",
                    "product": "smoke fixture",
                    "vulnerable_baseline": "1.0",
                    "fix_commit": f"fix-{index}",
                    "mechanism": f"verified mechanism {index}",
                    "precondition": required,
                    "requires_capabilities": [required],
                    "grants_capabilities": [granted],
                    "resource_effects": [granted],
                    "business_fit": "Used only to exercise ordered path validation.",
                    "selection_band": "core",
                    "selection_rationale": "Test fixture.",
                    "triage_status": "selected",
                    "artifact_pair_status": "registry-pair",
                    "public_poc_screen": "pass",
                    "live_reproduction": "pass",
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
                "id": "approved-two-hop",
                "candidate_ids": ["candidate-1", "candidate-2"],
                "target_goal_id": "read-status",
                "target_capability": "integrity:target-record",
                "rationale": "A connected two-hop test chain.",
                "status": "approved",
            }
        ]
        return raw

    def test_approved_candidate_path_validates_as_ordered_capability_chain(self):
        plan = RangePlan.model_validate(self._two_hop_plan())
        self.assertEqual(plan.candidate_paths[0].status, "approved")

    def test_selected_weakness_rejects_unselected_candidate(self):
        raw = self._two_hop_plan()
        raw["weakness_candidates"][0]["triage_status"] = "candidate"
        with self.assertRaisesRegex(ValidationError, "triage_status"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_rejects_disconnected_order(self):
        raw = self._two_hop_plan()
        raw["candidate_paths"][0]["candidate_ids"] = [
            "candidate-2",
            "candidate-1",
        ]
        with self.assertRaisesRegex(ValidationError, "continuous chain"):
            RangePlan.model_validate(raw)

    def test_approved_candidate_path_must_reach_resource_goal_capability(self):
        raw = self._two_hop_plan()
        raw["candidate_paths"][0]["target_capability"] = "integrity:other-record"
        with self.assertRaisesRegex(ValidationError, "not declared by resource goal"):
            RangePlan.model_validate(raw)

    def test_refuses_to_silently_drop_unimplemented_weaknesses(self):
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
            with self.assertRaisesRegex(ValueError, "weakness catalog deployment"):
                render_compose(bundle, catalog, Path(temp), Path(temp) / "out")

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


if __name__ == "__main__":
    unittest.main()
