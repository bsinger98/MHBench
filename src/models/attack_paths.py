"""
Attack path models for cyberrange specifications.

This module contains models for defining attack paths and steps in a cyberrange,
representing how an attacker can move laterally through the network to reach goals.
"""

from abc import ABC, abstractmethod
from uuid import UUID, uuid4
from typing import List, Union, Optional
from pydantic import BaseModel, Field, field_validator

from src.models.vulnerabilities import (
    LateralMovementVulnerability,
    PrivilegeEscalationVulnerability,
)


class AttackStep(BaseModel, ABC):
    """
    Base class for attack steps.

    All attack steps share some common properties but have different
    validation rules and semantics.
    """

    @abstractmethod
    def get_source_host_id(self) -> UUID:
        """Get the source host ID for this step."""
        pass

    @abstractmethod
    def get_target_host_id(self) -> UUID:
        """Get the target host ID for this step."""
        pass

    @abstractmethod
    def get_target_user_id(self) -> UUID:
        """Get the target user ID for this step."""
        pass

    @abstractmethod
    def get_source_user_id(self) -> UUID:
        """Get the source user ID for this step."""
        pass


class LateralMovementStep(AttackStep):
    """
    Represents lateral movement from one host to another.

    This is the classic "hop" in an attack path where an attacker
    moves from a compromised host to a new target host.
    """

    from_host_id: UUID
    to_host_id: UUID
    from_user_id: UUID
    to_user_id: UUID
    vulnerability: Optional[LateralMovementVulnerability] = None

    @field_validator("to_host_id")
    @classmethod
    def hosts_must_be_different(cls, v, info):
        if info.data.get("from_host_id") and v == info.data["from_host_id"]:
            raise ValueError("Lateral movement must be between different hosts")
        return v

    def get_source_host_id(self) -> UUID:
        return self.from_host_id

    def get_target_host_id(self) -> UUID:
        return self.to_host_id

    def get_source_user_id(self) -> UUID:
        return self.from_user_id

    def get_target_user_id(self) -> UUID:
        return self.to_user_id


class PrivilegeEscalationStep(AttackStep):
    """
    Represents privilege escalation on the same host.

    This represents moving from one user to another user with higher
    privileges on the same host (e.g., www-data to root).
    """

    host_id: UUID
    from_user_id: UUID
    to_user_id: UUID
    vulnerability: Optional[PrivilegeEscalationVulnerability] = None

    @field_validator("to_user_id")
    @classmethod
    def users_must_be_different(cls, v, info):
        if info.data.get("from_user_id") and v == info.data["from_user_id"]:
            raise ValueError("Privilege escalation must be between different users")
        return v

    def get_source_host_id(self) -> UUID:
        return self.host_id

    def get_target_host_id(self) -> UUID:
        return self.host_id

    def get_source_user_id(self) -> UUID:
        return self.from_user_id

    def get_target_user_id(self) -> UUID:
        return self.to_user_id


class AttackPath(BaseModel):
    """
    A complete path from the initial foothold to a goal host.

    Represents a sequence of attack steps that an attacker can follow
    to reach a target host from a starting position.
    """

    id: UUID = Field(default_factory=uuid4)
    start_host_id: UUID
    start_user_id: UUID
    target_host_id: UUID
    target_user_id: UUID
    steps: List[Union[LateralMovementStep, PrivilegeEscalationStep]] = Field(
        min_length=1
    )
    metadata: dict = Field(default_factory=dict)

    def get_hop_host_ids(self) -> List[UUID]:
        """
        Convenience method: ordered list of hosts traversed (including start & target).

        Returns:
            List of UUIDs representing the complete path through hosts
        """
        return [self.start_host_id] + [step.get_target_host_id() for step in self.steps]

    def get_all_host_ids(self) -> set[UUID]:
        """
        Get all unique host IDs involved in this attack path.

        Returns:
            Set of UUIDs for all hosts in the path
        """
        return set(self.get_hop_host_ids())

    def get_all_user_ids(self) -> set[UUID]:
        """
        Get all unique user IDs involved in this attack path.

        Returns:
            Set of UUIDs for all users in the path
        """
        user_ids = set()
        for step in self.steps:
            if isinstance(step, LateralMovementStep):
                if step.from_user_id:
                    user_ids.add(step.from_user_id)
                if step.to_user_id:
                    user_ids.add(step.to_user_id)
            elif isinstance(step, PrivilegeEscalationStep):
                user_ids.add(step.from_user_id)
                user_ids.add(step.to_user_id)
        return user_ids

    def validate_path_continuity(self) -> bool:
        """
        Validate that the attack path is continuous (each step connects properly).

        Returns:
            True if the path is valid, False otherwise
        """
        if not self.steps:
            return False

        # Check first step starts from the correct host
        if (
            self.steps[0].get_source_host_id() != self.start_host_id
            or self.steps[0].get_source_user_id() != self.start_user_id
        ):
            return False

        # Check each step connects to the next
        for i in range(len(self.steps) - 1):
            current_step = self.steps[i]
            next_step = self.steps[i + 1]

            # The destination host of current step should match source host of next step
            if current_step.get_target_host_id() != next_step.get_source_host_id():
                return False

            # If we're doing privilege escalation followed by another step,
            # check user context continuity
            if isinstance(current_step, PrivilegeEscalationStep):
                if isinstance(next_step, LateralMovementStep):
                    # The user we escalated to should be the user doing the lateral movement
                    if (
                        next_step.from_user_id
                        and current_step.to_user_id != next_step.from_user_id
                    ):
                        return False
                elif isinstance(next_step, PrivilegeEscalationStep):
                    # Chain privilege escalations
                    if current_step.to_user_id != next_step.from_user_id:
                        return False

        # Check last step ends at target
        if (
            self.steps[-1].get_target_host_id() != self.target_host_id
            or self.steps[-1].get_target_user_id() != self.target_user_id
        ):
            return False

        return True
