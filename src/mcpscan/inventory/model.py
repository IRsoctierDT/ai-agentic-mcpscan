# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Pure asset model for the AI/MCP inventory (VISION Tier 1).

The inventory answers *what AI systems exist here* — it classifies what the
scanner already discovers (host configs, declared servers, listening sockets)
into a typed asset list. Like ``domain``, this module is frozen, enum-driven,
and contains no I/O.

An :class:`Asset` is an observation, not a judgment: inventory carries no
severity and no findings. Posture assessment stays in ``scan`` (and, mapped to
frameworks, in Tier 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

INVENTORY_SCHEMA_VERSION = "1.0"


class AssetKind(Enum):
    """What class of AI-infrastructure component an asset is."""

    AGENT_HOST = "agent_host"  # an agent/IDE host app with an MCP config (Claude, Cursor, …)
    MCP_SERVER = "mcp_server"  # a declared or running MCP server
    MODEL_SERVER = "model_server"  # local model runtime (Ollama, vLLM, LM Studio, llama.cpp)
    INFERENCE_ENDPOINT = "inference_endpoint"  # OpenAI-compatible API surface
    LLM_GATEWAY = "llm_gateway"  # LLM proxy/router (LiteLLM, …)
    VECTOR_DB = "vector_db"  # vector database (Qdrant, Chroma, Weaviate, Milvus)


class AssetSource(Enum):
    """How the asset was observed."""

    CONFIG = "config"  # declared in a host config file
    SOCKET = "socket"  # observed listening on the machine


class Confidence(Enum):
    """How strong the classification evidence is, ordered strongest-first.

    ``HIGH`` requires a positive identification (exact process name or an
    endpoint fingerprint match); ``MEDIUM`` a strong hint (a generic
    OpenAI-compatible surface); ``LOW`` a default-port hint only.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Asset:
    """One classified AI-infrastructure component.

    ``evidence`` holds only strings *this tool* composed (e.g. ``"process name
    'ollama'"``); remote response bodies are never stored — a probed service is
    an untrusted input and its bytes must not reach a report.
    """

    kind: AssetKind
    product: str
    source: AssetSource
    location: str  # config path (CONFIG) or "ip:port" (SOCKET)
    confidence: Confidence
    evidence: tuple[str, ...]
    host: str | None = None  # the agent host whose config declared it (CONFIG)
    server_name: str | None = None  # declared server name (CONFIG)
    bind_addr: str | None = None  # SOCKET only
    port: int | None = None  # SOCKET only
    pid: int | None = None  # SOCKET only
    proc_name: str | None = None  # SOCKET only


@dataclass(frozen=True)
class Inventory:
    """The full result of one inventory collection."""

    schema_version: str
    assets: tuple[Asset, ...] = field(default_factory=tuple)
    inspection_incomplete: bool = False
