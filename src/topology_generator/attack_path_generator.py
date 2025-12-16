"""
Attack path generation utilities for random topologies.

This module builds simple, valid attack paths from an initial foothold in the
external subnet to every goal host in a given `NetworkTopology`.

Design assumptions:
- Initial access is obtained on a host inside the single external subnet.
- Lateral movement occurs hop-by-hop across subnets using simple pivots.
- Paths may share steps and re-use hosts across goals.
"""

from __future__ import annotations

import random
from typing import List, Optional

from src.models import (
    NetworkTopology,
    Host,
    User,
    AttackPath,
    LateralMovementStep,
    PrivilegeEscalationStep,
    JSONDataExfiltrationGoal,
)


class AttackPathGenerator:
    """Generates naive attack paths from an external foothold to goals."""

    def generate_paths_for_topology(
        self, topology: NetworkTopology
    ) -> List[AttackPath]:
        external_subnet = self._get_external_subnet(topology)
        if external_subnet is None or not external_subnet.hosts:
            return []

        if topology.attacker_host is None:
            raise Exception("Attacker host not found")

        # Initial compromised host and user within the external subnet
        attacker_host = topology.attacker_host
        attacker_user = attacker_host.get_root_user()

        attack_paths: List[AttackPath] = []
        for goal in topology.goals:
            target_host = topology.get_host_by_id(goal.target_host_id)
            if target_host is None:
                raise Exception(f"Target host {goal.target_host_id} not found")

            # Resolve target user if provided; default to root otherwise
            target_user = self._resolve_goal_target_user(topology, goal, target_host)

            steps: list = []

            # Randomly choose a host in the external subnet to start from
            current_host = random.choice(external_subnet.hosts)
            current_user = random.choice(current_host.users)
            # Add lateral movement step from attacker host to initial host
            steps.append(
                LateralMovementStep(
                    from_host_id=attacker_host.id,
                    to_host_id=current_host.id,
                    from_user_id=attacker_user.id,
                    to_user_id=current_user.id,
                )
            )

            # Find a subnet route from initial host to target host
            from_subnet = topology.get_subnet_for_host(current_host)
            to_subnet = topology.get_subnet_for_host(target_host)
            subnet_path: Optional[List[str]] = None
            if from_subnet and to_subnet:
                subnet_path = topology.find_subnet_path(
                    from_subnet.name, to_subnet.name
                )

            # Walk subnets hop-by-hop and pick a pivot host per subnet
            if subnet_path is None:
                # If there is no subnet path but hosts are the same subnet, no LM needed
                subnet_path = [from_subnet.name] if from_subnet else []

            # Build lateral movements across adjacent subnet pairs
            # We already "are" in the first subnet on `current_host`
            for i in range(1, len(subnet_path)):
                next_subnet_name = subnet_path[i]
                next_subnet = topology.get_subnet_by_name(next_subnet_name)
                if next_subnet is None or not next_subnet.hosts:
                    continue

                # Choose a random pivot on the next subnet
                next_host = random.choice(next_subnet.hosts)
                next_user = (
                    self._get_non_root_user(next_host) or next_host.get_root_user()
                )

                steps.append(
                    LateralMovementStep(
                        from_host_id=current_host.id,
                        to_host_id=next_host.id,
                        from_user_id=current_user.id,
                        to_user_id=next_user.id,
                    )
                )

                # Update pivot for next hop
                current_host = next_host
                current_user = next_user

            # If the final pivot host is not the target host, add one last hop within the same subnet
            if current_host.id != target_host.id:
                # Lateral movement to the actual target host (same subnet assumed reachable)
                next_user = (
                    self._get_non_root_user(target_host) or target_host.get_root_user()
                )
                steps.append(
                    LateralMovementStep(
                        from_host_id=current_host.id,
                        to_host_id=target_host.id,
                        from_user_id=current_user.id,
                        to_user_id=next_user.id,
                    )
                )
                current_host = target_host
                current_user = next_user

            # If the current user on target host is not the goal's target user, escalate
            if current_user.id != target_user.id:
                steps.append(
                    PrivilegeEscalationStep(
                        host_id=target_host.id,
                        from_user_id=current_user.id,
                        to_user_id=target_user.id,
                    )
                )

            # If we are already on the target host with the target user and have no steps yet,
            # add a trivial escalation to satisfy min_length=1 for steps
            if not steps:
                # Escalate to root and back to target user to create a minimal valid chain
                root_user = target_host.get_root_user()
                if current_user.id != root_user.id:
                    steps.append(
                        PrivilegeEscalationStep(
                            host_id=target_host.id,
                            from_user_id=current_user.id,
                            to_user_id=root_user.id,
                        )
                    )
                    current_user = root_user
                if current_user.id != target_user.id:
                    steps.append(
                        PrivilegeEscalationStep(
                            host_id=target_host.id,
                            from_user_id=current_user.id,
                            to_user_id=target_user.id,
                        )
                    )

            attack_paths.append(
                AttackPath(
                    start_host_id=attacker_host.id,
                    start_user_id=attacker_user.id,
                    target_host_id=target_host.id,
                    target_user_id=target_user.id,
                    steps=steps,
                )
            )

        return attack_paths

    def assign_vulnerabilities(
        self, path: AttackPath, topology: NetworkTopology
    ) -> AttackPath:
        """Assign concrete vulnerabilities to a previously generated path skeleton.

        This is a placeholder; specific selection logic can be implemented later.
        Currently leaves steps untouched.
        """
        path.metadata["vulnerabilities_assigned"] = True
        return path

    def _get_external_subnet(self, topology: NetworkTopology):
        for subnet in topology.get_all_subnets():
            if subnet.external:
                return subnet
        return None

    def _get_non_root_user(self, host: Host) -> Optional[User]:
        for user in host.users:
            if user.username != "root":
                return user
        return None

    def _resolve_goal_target_user(
        self,
        topology: NetworkTopology,
        goal,
        target_host: Host,
    ) -> User:
        # JSONDataExfiltrationGoal provides a username for the target host
        if isinstance(goal, JSONDataExfiltrationGoal):
            user = target_host.get_user_by_username(goal.host_user)
            if user is not None:
                return user
        # Default to root if unspecified or not found
        return target_host.get_root_user()
