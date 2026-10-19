"""Shared controlled vocabulary for ASL.

Every analyzer speaks in these terms so that risk fusion, fingerprinting and
audit records stay comparable across the pipeline.  Kept in one module (rather
than scattered across the model files) because the vocabulary *is* the contract
between subsystems.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """`str` mixin enum so values serialise cleanly through Pydantic/JSON/SQLite."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class Capability(StrEnum):
    """Semantic capabilities (spec section 3)."""

    READ = "READ"
    WRITE = "WRITE"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    DOWNLOAD = "DOWNLOAD"
    UPLOAD = "UPLOAD"
    EMAIL = "EMAIL"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    AUTHENTICATE = "AUTHENTICATE"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    SENSOR_ACCESS = "SENSOR_ACCESS"


#: Relative destructive weight of a capability, 0-100.  Used by the capability
#: extractor and (later) the risk engine; never used as a decision on its own.
CAPABILITY_WEIGHT: dict[Capability, int] = {
    Capability.READ: 10,
    Capability.NETWORK: 25,
    Capability.DOWNLOAD: 40,
    Capability.UPLOAD: 55,
    Capability.WRITE: 45,
    Capability.MODIFY: 50,
    Capability.DATABASE: 45,
    Capability.EMAIL: 50,
    Capability.AUTHENTICATE: 55,
    Capability.SENSOR_ACCESS: 45,
    Capability.EXECUTE: 80,
    Capability.DELETE: 85,
    Capability.PRIVILEGE_CHANGE: 90,
}


class ToolCategory(StrEnum):
    """Coarse family of a tool.  Configurable per tool in the tool registry."""

    SEARCH = "SEARCH"
    WEB = "WEB"
    COMPUTATION = "COMPUTATION"
    COMMUNICATION = "COMMUNICATION"
    FILESYSTEM = "FILESYSTEM"
    CODE_EXECUTION = "CODE_EXECUTION"
    SYSTEM = "SYSTEM"
    DATABASE = "DATABASE"
    NETWORK = "NETWORK"
    IDENTITY = "IDENTITY"
    SENSOR = "SENSOR"
    UNKNOWN = "UNKNOWN"


class Intent(StrEnum):
    """Task-level intent (spec section 4)."""

    INFORMATION_RETRIEVAL = "INFORMATION_RETRIEVAL"
    COMMUNICATION = "COMMUNICATION"
    FILE_MANAGEMENT = "FILE_MANAGEMENT"
    DATA_PROCESSING = "DATA_PROCESSING"
    DATA_TRANSFER = "DATA_TRANSFER"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CODE_EXECUTION = "CODE_EXECUTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DESTRUCTIVE_ACTION = "DESTRUCTIVE_ACTION"
    UNKNOWN = "UNKNOWN"


class Decision(StrEnum):
    """Terminal authorization decisions (spec section 16)."""

    ALLOW = "ALLOW"
    ALLOW_WITH_LOG = "ALLOW_WITH_LOG"
    CHALLENGE = "CHALLENGE"
    SANDBOX = "SANDBOX"
    BLOCK = "BLOCK"


class DecisionPath(StrEnum):
    """Which evaluation path produced a decision."""

    FAST_PATH = "FAST_PATH_ALLOW"
    FULL_ANALYSIS = "FULL_ASL_ANALYSIS"


class Environment(StrEnum):
    SANDBOX = "sandbox"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Severity(StrEnum):
    """Severity of a single analyzer finding."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_SCORE: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 15,
    Severity.MEDIUM: 40,
    Severity.HIGH: 70,
    Severity.CRITICAL: 95,
}


class ResourceClass(StrEnum):
    """What *kind of thing* an argument points at.

    This is the tool-name-independent vocabulary that makes semantically
    equivalent workflows produce equivalent fingerprints: `filesystem.delete`
    and `shell.execute("rm -rf ...")` both resolve to FILE / SYSTEM_PATH.
    """

    NONE = "NONE"
    PUBLIC_CONTENT = "PUBLIC_CONTENT"
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    SYSTEM_PATH = "SYSTEM_PATH"
    CREDENTIAL_STORE = "CREDENTIAL_STORE"
    PRODUCTION_RESOURCE = "PRODUCTION_RESOURCE"
    USER_DATA = "USER_DATA"
    DATABASE_TABLE = "DATABASE_TABLE"
    SENSITIVE_TABLE = "SENSITIVE_TABLE"
    INTERNAL_ENDPOINT = "INTERNAL_ENDPOINT"
    EXTERNAL_ENDPOINT = "EXTERNAL_ENDPOINT"
    EMAIL_RECIPIENT_INTERNAL = "EMAIL_RECIPIENT_INTERNAL"
    EMAIL_RECIPIENT_EXTERNAL = "EMAIL_RECIPIENT_EXTERNAL"
    CODE = "CODE"
    BINARY = "BINARY"
    UNKNOWN = "UNKNOWN"


#: Sensitivity multiplier hint per resource class (0-100).
RESOURCE_SENSITIVITY: dict[ResourceClass, int] = {
    ResourceClass.NONE: 0,
    ResourceClass.PUBLIC_CONTENT: 5,
    ResourceClass.FILE: 25,
    ResourceClass.DIRECTORY: 40,
    ResourceClass.CODE: 45,
    ResourceClass.BINARY: 65,
    ResourceClass.USER_DATA: 55,
    ResourceClass.DATABASE_TABLE: 45,
    ResourceClass.SENSITIVE_TABLE: 85,
    ResourceClass.INTERNAL_ENDPOINT: 55,
    ResourceClass.EXTERNAL_ENDPOINT: 45,
    ResourceClass.EMAIL_RECIPIENT_INTERNAL: 25,
    ResourceClass.EMAIL_RECIPIENT_EXTERNAL: 50,
    ResourceClass.SYSTEM_PATH: 85,
    ResourceClass.CREDENTIAL_STORE: 95,
    ResourceClass.PRODUCTION_RESOURCE: 90,
    ResourceClass.UNKNOWN: 30,
}


class Scope(StrEnum):
    """Blast radius of an action on its resource."""

    NONE = "NONE"
    SINGLE = "SINGLE"
    MULTIPLE = "MULTIPLE"
    RECURSIVE = "RECURSIVE"
    UNBOUNDED = "UNBOUNDED"


SCOPE_WEIGHT: dict[Scope, float] = {
    Scope.NONE: 0.0,
    Scope.SINGLE: 1.0,
    Scope.MULTIPLE: 1.25,
    Scope.RECURSIVE: 1.6,
    Scope.UNBOUNDED: 2.0,
}


class EdgeType(StrEnum):
    """Relationship between two behavior-graph nodes."""

    SEQUENCE = "SEQUENCE"        # b happened after a in the same session
    DATA_FLOW = "DATA_FLOW"      # b consumes a resource a produced/touched
    CAPABILITY = "CAPABILITY"    # invocation node -> capability node
    RESOURCE = "RESOURCE"        # invocation node -> resource node


class NodeKind(StrEnum):
    INVOCATION = "INVOCATION"
    CAPABILITY = "CAPABILITY"
    RESOURCE = "RESOURCE"
