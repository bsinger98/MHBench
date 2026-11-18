"""Compile a reviewed scenario/range pair and task assets into a Harbor task."""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from .compose_backend import ServiceCatalog, load_bundle, load_yaml, render_compose


def _entry_instruction(bundle) -> str:
    entry = bundle.range.entry_state
    service = next(
        service for service in bundle.range.services if service.id == entry.service_id
    )
    endpoint = entry.endpoint
    if endpoint is None:
        port = service.ports[0] if service.ports else 80
        endpoint = f"http://{service.id}:{port}/"

    lines = [
        "# Access",
        "",
        f"The service is available at `{endpoint}`.",
    ]
    if entry.credentials:
        lines.extend(["", "Use these credentials:", ""])
        lines.extend(
            f"- {name}: `{value}`"
            for name, value in entry.credentials.items()
        )
    if bundle.range.agent and bundle.range.agent.tools:
        lines.extend(
            [
                "",
                "The shell includes: "
                + ", ".join(f"`{tool}`" for tool in bundle.range.agent.tools)
                + ".",
            ]
        )
    return "\n".join(lines) + "\n"


def _copy_task_assets(assets_dir: Path, output_dir: Path) -> None:
    for name in ("task.toml", "README.md"):
        source = assets_dir / name
        if not source.is_file():
            raise ValueError(f"required Harbor task asset is missing: {source}")
        shutil.copy2(source, output_dir / name)

    for name in ("tests", "solution", "hint"):
        source = assets_dir / name
        if not source.exists():
            continue
        if not source.is_dir():
            raise ValueError(f"Harbor task asset must be a directory: {source}")
        destination = output_dir / name
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(source, destination)


@click.command()
@click.option(
    "--scenario",
    "scenario_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--range-plan",
    "range_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalog",
    "catalog_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalog-root",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--task-assets",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--output",
    "output_dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
)
def main(
    scenario_file: Path,
    range_file: Path,
    catalog_file: Path,
    catalog_root: Path,
    task_assets: Path,
    output_dir: Path,
) -> None:
    """Write an environment plus Harbor task metadata and authored grader assets."""
    try:
        bundle = load_bundle(scenario_file, range_file)
        catalog = ServiceCatalog.model_validate(load_yaml(catalog_file))
        output_dir.mkdir(parents=True, exist_ok=True)
        environment_dir = output_dir / "environment"
        render_compose(
            bundle,
            catalog,
            catalog_root=catalog_root,
            output_dir=environment_dir,
        )
        _copy_task_assets(task_assets, output_dir)
        (output_dir / "instruction.md").write_text(_entry_instruction(bundle))
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Rendered Harbor task: {output_dir}")


if __name__ == "__main__":
    main()
