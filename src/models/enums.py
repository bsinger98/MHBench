"""
Enumeration types for cyberrange specifications.

This module contains all the enum definitions used throughout the specification language.
"""

from enum import Enum


class OSType(str, Enum):
    """Supported operating systems."""

    UBUNTU_20 = "Ubuntu20"
    KALI_LINUX = "KaliLinux"


class FlavorType(str, Enum):
    """Compute instance flavors/sizes."""

    TINY = "p2.tiny"
    SMALL = "p2.small"
    MEDIUM = "p2.medium"
    LARGE = "p2.large"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be deployed."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


class GoalType(str, Enum):
    """Types of goals/objectives in the cyberrange."""

    DATA_EXFILTRATION = "data_exfiltration"
    HOST_ACCESS = "host_access"


class ProtocolType(str, Enum):
    """Network protocols."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
