"""Render a validated scenario/range pair as a portable Compose environment.

This backend only compiles reviewed service templates and topology. Weakness
deployment is intentionally a separate catalog/adapter concern; a generated
Compose file must not imply that a referenced weakness has been installed.
"""

from __future__ import annotations

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
) -> Path:
    """Render Compose and copy any catalog-owned Docker build contexts."""
    if bundle.range.weaknesses:
        raise ValueError(
            "refusing to render a task environment while weakness catalog "
            "deployment is not implemented; remove weakness instances only "
            "for a baseline Compose smoke test"
        )
    templates = catalog.by_ref()
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


def load_bundle(scenario_file: Path, range_file: Path) -> ScenarioBundle:
    scenario = ScenarioPlan.model_validate(load_yaml(scenario_file))
    range_plan = RangePlan.model_validate(load_yaml(range_file))
    return ScenarioBundle(scenario=scenario, range=range_plan)
