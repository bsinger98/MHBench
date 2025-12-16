"""
Virtual attacker models for attack path specifications.

This module contains models for representing external attackers that are not part
of the network topology but are needed for attack path modeling.
"""

from src.models.network import Host
from src.models.enums import OSType


def create_default_external_attacker() -> Host:
    """Create a default external attacker."""
    return Host(name="external_attacker", os_type=OSType.KALI_LINUX)
