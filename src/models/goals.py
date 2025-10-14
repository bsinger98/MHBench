from pydantic import BaseModel, field_serializer, Field
from uuid import UUID
from typing import Union

from .enums import GoalType


class Goal(BaseModel):
    """Goal/objective specification."""

    type: GoalType
    target_host_id: UUID
    target_user_id: UUID

    @field_serializer("target_host_id", "target_user_id")
    def serialize_uuid(self, value: UUID) -> str:
        """Serialize UUID as string for JSON compatibility."""
        return str(value)


class DataExfiltrationGoal(Goal):
    """Data exfiltration goal."""

    type: GoalType = GoalType.DATA_EXFILTRATION
    playbook_path: str
    host_ip: str


class JSONDataExfiltrationGoal(DataExfiltrationGoal):
    """JSON data exfiltration goal."""

    playbook_path: str = "goals/data/addData.yml"
    src_path: str = "data.json"
    dst_path: str
    host_user: str


# Union type for polymorphic Goal serialization
GoalUnion = Union[JSONDataExfiltrationGoal, DataExfiltrationGoal, Goal]
