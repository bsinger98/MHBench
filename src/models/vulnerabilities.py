from enum import Enum

from pydantic import BaseModel

from .enums import VulnerabilityType


class MergeStrategy(str, Enum):
    """How installations of this vulnerability can be merged/deduplicated."""

    NO_MERGE = "no_merge"  # Each use requires a separate install
    BY_HOST = "by_host"  # One install per host suffices (e.g., privilege escalation)
    BY_TARGET_HOST = (
        "by_target_host"  # One install on the target host suffices for many sources
    )
    BY_EDGE = "by_edge"  # One install per (from_host -> to_host) pair


class Vulnerability(BaseModel):
    """Vulnerability specification."""

    type: VulnerabilityType
    playbook_path: str
    merge_strategy: MergeStrategy = MergeStrategy.NO_MERGE
    internal_only: bool = False

    from_host_ip: str = ""
    to_host_ip: str = ""
    from_user: str = ""
    to_user: str = ""


class LateralMovementVulnerability(Vulnerability):
    type: VulnerabilityType = VulnerabilityType.LATERAL_MOVEMENT


class PrivilegeEscalationVulnerability(Vulnerability):
    type: VulnerabilityType = VulnerabilityType.PRIVILEGE_ESCALATION


class ApacheStrutsVulnerability(LateralMovementVulnerability):
    """Apache Struts vulnerability."""

    playbook_path: str = "vulnerabilities/apacheStruts/setupStruts.yml"
    # Service is host-wide; one install suffices for all users on the host
    merge_strategy: MergeStrategy = MergeStrategy.BY_HOST


class NetcatShellVulnerability(LateralMovementVulnerability):
    """Netcat shell vulnerability."""

    playbook_path: str = "vulnerabilities/NetcatShell.yml"
    # Treat as non-mergeable to model per-connection or credential-like constraints
    merge_strategy: MergeStrategy = MergeStrategy.BY_HOST


class MisconfiguredSSHKeysVulnerability(LateralMovementVulnerability):
    """Misconfigured SSH keys vulnerability."""

    playbook_path: str = "deployment_instance/setup_server_ssh_keys/setup_ssh_keys.yml"
    # Treat as non-mergeable to model per-connection or credential-like constraints
    merge_strategy: MergeStrategy = MergeStrategy.BY_HOST


class SudoBaronVulnerability(PrivilegeEscalationVulnerability):
    """Sudo Baron privilege escalation vulnerability."""

    playbook_path: str = "vulnerabilities/privledge_escalation/sudobaron/sudobaron.yml"
    merge_strategy: MergeStrategy = MergeStrategy.BY_HOST


class WriteablePasswdVulnerability(PrivilegeEscalationVulnerability):
    """Writeable /etc/passwd privilege escalation vulnerability."""

    playbook_path: str = (
        "vulnerabilities/privledge_escalation/writeablePasswd/writeablePasswd.yml"
    )
    merge_strategy: MergeStrategy = MergeStrategy.BY_HOST
