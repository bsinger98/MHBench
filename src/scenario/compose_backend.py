"""Render a validated scenario/range pair as a portable Compose environment.

Service templates and explicitly selected weaknesses resolve through separate
reviewed catalogs. The initial weakness adapter supports deterministic file
overlays on build-backed services; unsupported or unresolved weaknesses fail
closed rather than being silently omitted.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .spec import RangePlan, ScenarioBundle, ScenarioPlan


class ServiceTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    catalog_ref: str
    delivery: Literal["image", "build"]
    image: str | None = None
    context: str | None = None
    dockerfile: str = "Dockerfile"
    default_expose: list[int] = Field(default_factory=list)
    healthcheck: list[str] | None = None

    @model_validator(mode="after")
    def validate_delivery(self) -> "ServiceTemplate":
        if self.delivery == "image" and (not self.image or self.context):
            raise ValueError("image delivery requires image and forbids context")
        if self.delivery == "build" and (not self.context or self.image):
            raise ValueError("build delivery requires context and forbids image")
        return self


class ServiceCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    services: list[ServiceTemplate] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_refs(self) -> "ServiceCatalog":
        refs = [entry.catalog_ref for entry in self.services]
        if len(refs) != len(set(refs)):
            raise ValueError("service catalog_ref values must be unique")
        return self

    def by_ref(self) -> dict[str, ServiceTemplate]:
        return {entry.catalog_ref: entry for entry in self.services}


class FileOverlay(BaseModel):
    """A reviewed file replacement installed into one service image."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str


class WeaknessTemplate(BaseModel):
    """Deterministic file-overlay adapter for one reviewed weakness candidate."""

    model_config = ConfigDict(extra="forbid")

    catalog_ref: str
    candidate_ids: list[str] = Field(min_length=1)
    service_catalog_ref: str
    file_overlays: list[FileOverlay] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_overlay_paths(self) -> "WeaknessTemplate":
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError(
                f"weakness template {self.catalog_ref} repeats candidate IDs"
            )
        for overlay in self.file_overlays:
            source = PurePosixPath(overlay.source)
            target = PurePosixPath(overlay.target)
            if (
                source.is_absolute()
                or not source.parts
                or ".." in source.parts
            ):
                raise ValueError(
                    f"weakness template {self.catalog_ref} overlay source "
                    "must be a relative path without '..'"
                )
            if (
                not target.is_absolute()
                or ".." in target.parts
                or target == PurePosixPath("/")
            ):
                raise ValueError(
                    f"weakness template {self.catalog_ref} overlay target "
                    "must be an absolute container file path"
                )
        return self


class WeaknessCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    weaknesses: list[WeaknessTemplate] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_refs(self) -> "WeaknessCatalog":
        refs = [entry.catalog_ref for entry in self.weaknesses]
        if len(refs) != len(set(refs)):
            raise ValueError("weakness catalog_ref values must be unique")
        return self

    def by_ref(self) -> dict[str, WeaknessTemplate]:
        return {entry.catalog_ref: entry for entry in self.weaknesses}


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _copy_build_context(
    template: ServiceTemplate,
    catalog_root: Path,
    output_dir: Path,
    service_id: str,
) -> dict[str, str]:
    context_rel = PurePosixPath(template.context or "")
    if context_rel.is_absolute() or ".." in context_rel.parts:
        raise ValueError(
            f"service template {template.catalog_ref} context must be "
            "a relative path without '..'"
        )
    dockerfile_rel = PurePosixPath(template.dockerfile)
    if dockerfile_rel.is_absolute() or ".." in dockerfile_rel.parts:
        raise ValueError(
            f"service template {template.catalog_ref} Dockerfile must "
            "be relative to its context"
        )
    source = (catalog_root / Path(*context_rel.parts)).resolve()
    root = catalog_root.resolve()
    if not source.is_relative_to(root) or not source.is_dir():
        raise ValueError(
            f"build context for {template.catalog_ref} is missing or "
            "escapes the catalog root"
        )
    dockerfile_source = source / Path(*dockerfile_rel.parts)
    if (
        not dockerfile_source.resolve().is_relative_to(source)
        or not dockerfile_source.is_file()
    ):
        raise ValueError(
            f"Dockerfile for {template.catalog_ref} does not exist"
        )
    for item in source.rglob("*"):
        if item.is_symlink() and not item.resolve().is_relative_to(source):
            raise ValueError(
                f"build context for {template.catalog_ref} contains a "
                "symlink that escapes its context"
            )
    destination = output_dir / "build" / service_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return {
        "context": f"./build/{service_id}",
        "dockerfile": template.dockerfile,
    }


def _install_harbor_agent_dockerfile(
    template: ServiceTemplate,
    catalog_root: Path,
    output_dir: Path,
) -> None:
    """Install the attacker image recipe at Harbor's required environment/Dockerfile."""
    if template.delivery != "build":
        raise ValueError("Harbor agent environment must use a build template")
    context_rel = PurePosixPath(template.context or "")
    dockerfile_rel = PurePosixPath(template.dockerfile)
    if (
        context_rel.is_absolute()
        or ".." in context_rel.parts
        or dockerfile_rel.is_absolute()
        or ".." in dockerfile_rel.parts
    ):
        raise ValueError("agent build context and Dockerfile must stay in catalog root")
    source = (catalog_root / Path(*context_rel.parts)).resolve()
    root = catalog_root.resolve()
    dockerfile_source = source / Path(*dockerfile_rel.parts)
    if (
        not source.is_relative_to(root)
        or not source.is_dir()
        or not dockerfile_source.resolve().is_relative_to(source)
        or not dockerfile_source.is_file()
    ):
        raise ValueError("Harbor agent Dockerfile/context is missing or escapes catalog root")
    for item in source.rglob("*"):
        if item.is_symlink() and not item.resolve().is_relative_to(source):
            raise ValueError("Harbor agent context contains a symlink outside its root")
    payload = [item for item in source.iterdir() if item.name != template.dockerfile]
    if payload:
        raise ValueError(
            "agent Dockerfile context must currently contain only its Dockerfile; "
            "add a declared assets mechanism before using extra files"
        )
    shutil.copy2(dockerfile_source, output_dir / "Dockerfile")


def render_compose(
    bundle: ScenarioBundle,
    catalog: ServiceCatalog,
    catalog_root: Path,
    output_dir: Path,
    weakness_catalog: WeaknessCatalog | None = None,
) -> Path:
    """Render Compose, service contexts, and explicitly selected file overlays."""
    if bundle.range.weaknesses and weakness_catalog is None:
        raise ValueError(
            "weakness catalog deployment requires a reviewed weakness catalog"
        )
    templates = catalog.by_ref()
    weakness_templates = (
        weakness_catalog.by_ref() if weakness_catalog is not None else {}
    )
    selected_by_service: dict[str, list[tuple[WeaknessTemplate, str]]] = {}
    candidate_by_id = {
        candidate.id: candidate for candidate in bundle.range.weakness_candidates
    }
    service_by_id = {service.id: service for service in bundle.range.services}
    overlay_targets: dict[str, set[str]] = {}
    for weakness in bundle.range.weaknesses:
        candidate = candidate_by_id[weakness.candidate_id]
        weakness_template = weakness_templates.get(weakness.catalog_ref)
        if weakness_template is None:
            raise ValueError(
                f"weakness {weakness.id} has unresolved catalog_ref "
                f"{weakness.catalog_ref!r}"
            )
        if candidate.id not in weakness_template.candidate_ids:
            raise ValueError(
                f"weakness template {weakness_template.catalog_ref} does not "
                f"declare candidate {candidate.id}"
            )
        service_instance = service_by_id[weakness.service_id]
        if service_instance.catalog_ref != weakness_template.service_catalog_ref:
            raise ValueError(
                f"weakness template {weakness_template.catalog_ref} requires "
                f"service template {weakness_template.service_catalog_ref}, "
                f"not {service_instance.catalog_ref}"
            )
        service_template = templates.get(service_instance.catalog_ref)
        if service_template is None:
            raise ValueError(
                f"service {service_instance.id} has unresolved catalog_ref "
                f"{service_instance.catalog_ref!r}"
            )
        if service_template.delivery != "build":
            raise ValueError(
                f"weakness template {weakness_template.catalog_ref} requires "
                "a build-backed service; image-only overlay deployment is "
                "not supported"
            )
        targets = overlay_targets.setdefault(weakness.service_id, set())
        for overlay in weakness_template.file_overlays:
            if overlay.target in targets:
                raise ValueError(
                    f"multiple selected weaknesses replace "
                    f"{weakness.service_id}:{overlay.target}; define an "
                    "explicit compatible composition instead"
                )
            targets.add(overlay.target)
        selected_by_service.setdefault(weakness.service_id, []).append(
            (weakness_template, weakness.id)
        )

    networks = {network.id: network for network in bundle.range.networks}
    attached_networks: dict[str, list[str]] = {
        service.id: [] for service in bundle.range.services
    }
    for attachment in bundle.range.attachments:
        attached_networks[attachment.service_id].append(attachment.network_id)

    compose_services: dict[str, dict] = {}
    output_dir.mkdir(parents=True, exist_ok=True)
    for instance in bundle.range.services:
        template = templates.get(instance.catalog_ref)
        if template is None:
            raise ValueError(
                f"service {instance.id} has unresolved catalog_ref "
                f"{instance.catalog_ref!r}"
            )
        service: dict = {}
        service["restart"] = "unless-stopped"
        if template.delivery == "image":
            service["image"] = template.image
        else:
            service["build"] = _copy_build_context(
                template, catalog_root, output_dir, instance.id
            )
            selected = selected_by_service.get(instance.id, [])
            if selected:
                service["build"]["dockerfile"] = _install_weakness_overlays(
                    selected,
                    catalog_root,
                    output_dir / "build" / instance.id,
                    template.dockerfile,
                )
        expose = instance.ports or template.default_expose
        if expose:
            service["expose"] = [str(port) for port in expose]
        if template.healthcheck:
            service["healthcheck"] = {
                "test": template.healthcheck,
                "interval": "10s",
                "timeout": "5s",
                "retries": 5,
                "start_period": "10s",
            }
        if instance.depends_on:
            service["depends_on"] = instance.depends_on
        if instance.environment:
            service["environment"] = instance.environment
        service["networks"] = attached_networks[instance.id]
        compose_services[instance.id] = service

    if bundle.range.agent:
        agent = bundle.range.agent
        template = templates.get(agent.catalog_ref)
        if template is None:
            raise ValueError(
                f"agent environment has unresolved catalog_ref "
                f"{agent.catalog_ref!r}"
            )
        _install_harbor_agent_dockerfile(template, catalog_root, output_dir)
        agent_service: dict = {}
        agent_service.update(
            {
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": agent.network_ids,
            }
        )
        entry_instance = next(
            (
                instance
                for instance in bundle.range.services
                if instance.id == bundle.range.entry_state.service_id
            ),
            None,
        )
        entry_template = (
            templates[entry_instance.catalog_ref] if entry_instance else None
        )
        if entry_template and entry_template.healthcheck:
            agent_service["depends_on"] = {
                bundle.range.entry_state.service_id: {
                    "condition": "service_healthy"
                }
            }
        elif entry_instance:
            agent_service["depends_on"] = [bundle.range.entry_state.service_id]
        compose_services["main"] = agent_service

    compose_networks = {
        # Agent-facing and service-private segments have no direct external
        # route. Only an explicitly modeled egress network gets a gateway.
        network.id: {"internal": network.exposure != "egress"}
        for network in bundle.range.networks
    }
    document = {
        "services": compose_services,
        "networks": compose_networks,
    }
    output_path = output_dir / "docker-compose.yaml"
    output_path.write_text(
        yaml.safe_dump(document, sort_keys=False, default_flow_style=False)
    )
    return output_path


def _install_weakness_overlays(
    selected: list[tuple[WeaknessTemplate, str]],
    catalog_root: Path,
    build_context: Path,
    base_dockerfile: str,
) -> str:
    """Copy reviewed overlay files and append deterministic Dockerfile COPYs."""
    root = catalog_root.resolve()
    staged: list[tuple[str, str]] = []
    for template, weakness_id in selected:
        for index, overlay in enumerate(template.file_overlays):
            source_path = root / Path(*PurePosixPath(overlay.source).parts)
            source_cursor = source_path
            while source_cursor != root:
                if source_cursor.is_symlink():
                    raise ValueError(
                        f"overlay source {overlay.source!r} for "
                        f"{template.catalog_ref} traverses a symlink"
                    )
                source_cursor = source_cursor.parent
            source = source_path.resolve()
            if not source.is_relative_to(root) or not source.is_file():
                raise ValueError(
                    f"overlay source {overlay.source!r} for "
                    f"{template.catalog_ref} is missing or escapes catalog root"
                )
            safe_weakness_id = hashlib.sha256(
                weakness_id.encode("utf-8")
            ).hexdigest()[:16]
            relative = (
                Path("_mhbench")
                / "weaknesses"
                / safe_weakness_id
                / f"{index:03d}-{source.name}"
            )
            destination = build_context / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            staged.append((relative.as_posix(), overlay.target))

    original = build_context / base_dockerfile
    dockerfile_text = original.read_text()
    for source, target in staged:
        dockerfile_text += (
            "\nCOPY "
            + json.dumps([source, target])
            + "\n"
        )
    generated_name = "Dockerfile.mhbench"
    (build_context / generated_name).write_text(dockerfile_text)
    return generated_name


def load_bundle(scenario_file: Path, range_file: Path) -> ScenarioBundle:
    scenario = ScenarioPlan.model_validate(load_yaml(scenario_file))
    range_plan = RangePlan.model_validate(load_yaml(range_file))
    return ScenarioBundle(scenario=scenario, range=range_plan)
