"""CLI for rendering the scenario inputs through the Compose backend."""

from pathlib import Path

import click

from .compose_backend import (
    ServiceCatalog,
    WeaknessCatalog,
    load_bundle,
    load_yaml,
    render_compose,
)


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
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
)
@click.option(
    "--weakness-catalog",
    "weakness_catalog_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Reviewed catalog required when the range plan selects weaknesses.",
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
    weakness_catalog_file: Path | None,
    output_dir: Path,
) -> None:
    """Render Docker Compose and service build contexts from approved inputs."""
    try:
        bundle = load_bundle(scenario_file, range_file)
        catalog = ServiceCatalog.model_validate(load_yaml(catalog_file))
        weakness_catalog = (
            WeaknessCatalog.model_validate(load_yaml(weakness_catalog_file))
            if weakness_catalog_file
            else None
        )
        compose_file = render_compose(
            bundle,
            catalog,
            catalog_root=catalog_root,
            output_dir=output_dir,
            weakness_catalog=weakness_catalog,
        )
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Rendered Compose environment: {compose_file}")


if __name__ == "__main__":
    main()
