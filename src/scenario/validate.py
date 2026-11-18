"""Validate a scenario spec from YAML or JSON."""

from collections import Counter
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from .spec import ScenarioBundle, RangePlan, ScenarioPlan


@click.command()
@click.argument(
    "scenario_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.argument(
    "range_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
def main(scenario_file: Path, range_file: Path) -> None:
    """Validate a business SCENARIO_FILE and its concrete RANGE_FILE."""
    try:
        scenario = ScenarioPlan.model_validate(yaml.safe_load(scenario_file.read_text()))
        range_plan = RangePlan.model_validate(yaml.safe_load(range_file.read_text()))
        bundle = ScenarioBundle(scenario=scenario, range=range_plan)
    except (yaml.YAMLError, ValidationError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Valid scenario: {scenario.id} — {scenario.title}")
    click.echo(
        f"{len(scenario.workflows)} workflows, {len(scenario.systems)} business "
        f"systems, {len(range_plan.services)} services, "
        f"{len(range_plan.weaknesses)} weaknesses, {len(range_plan.goals)} "
        f"resource goals"
    )
    bands = Counter(item.selection_band for item in range_plan.weakness_candidates)
    if range_plan.weakness_candidates:
        band_summary = ", ".join(
            f"{band}={bands[band]}"
            for band in ("core", "adjacent", "alternate", "deferred")
            if bands[band]
        )
        click.echo(
            f"{len(range_plan.weakness_candidates)} weakness candidates "
            f"({band_summary}); none imply selection or deployment"
        )
        direct = range_plan.candidates_directly_reachable_from_entry()
        click.echo(
            f"{len(direct)} candidates have attacker capabilities satisfied at entry "
            "(environment preconditions are separate); "
            f"{len(range_plan.weakness_candidates) - len(direct)} need a justified "
            "capability bridge or a revised entry-state assumption"
        )
    if range_plan.candidate_paths:
        click.echo(
            f"{len(range_plan.candidate_paths)} explicit candidate-path "
            "hypotheses (unapproved; no automatic selection)"
        )


if __name__ == "__main__":
    main()
