"""
Virtual attacker models for attack path specifications.

This module contains models for representing external attackers that are not part
of the network topology but are needed for attack path modeling.
"""

from environment.models.network import Host
from environment.models.network import OSType


def create_default_external_attacker() -> Host:
    """Create a default external attacker."""
    return Host(name="external_attacker", os_type=OSType.KALI_LINUX)
