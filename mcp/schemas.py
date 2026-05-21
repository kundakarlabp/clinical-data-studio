from __future__ import annotations

MCP_PROTOCOL_VERSION = "2024-11-05"

READ_ONLY_TOOLS = {
    "search_studies": {
        "description": "List studies accessible to this read-only MCP token.",
        "scope": "mcp:studies:read",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    "get_study_summary": {
        "description": "Return aggregate study status without raw participant rows.",
        "scope": "mcp:summary:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}},
            "required": ["study_id"],
            "additionalProperties": False,
        },
    },
    "get_crf_dictionary": {
        "description": "Return CRF definitions and validation metadata only.",
        "scope": "mcp:crf:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}, "form_id": {"type": "integer"}},
            "required": ["study_id"],
            "additionalProperties": False,
        },
    },
    "get_missing_data_summary": {
        "description": "Return missing required field counts by form and field.",
        "scope": "mcp:missing-data:read",
        "inputSchema": {
            "type": "object",
            "properties": {
                "study_id": {"type": "integer"},
                "form_id": {"type": "integer"},
                "severity": {"type": "string", "enum": ["required_only", "all"]},
            },
            "required": ["study_id"],
            "additionalProperties": False,
        },
    },
    "get_deidentified_dataset_summary": {
        "description": "Return aggregate numeric and categorical summaries only.",
        "scope": "mcp:dataset-summary:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}, "form_id": {"type": "integer"}},
            "required": ["study_id"],
            "additionalProperties": False,
        },
    },
    "get_publication_opportunities": {
        "description": "Return safe publication or audit ideas from de-identified summaries.",
        "scope": "mcp:publication:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}},
            "required": ["study_id"],
            "additionalProperties": False,
        },
    },
    "get_cv_items": {
        "description": "Return academic workbench CV items without patient data.",
        "scope": "mcp:cv:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}, "category": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    "get_ai_audit_summary": {
        "description": "Return aggregate AI and MCP usage counts without prompt contents.",
        "scope": "mcp:audit-summary:read",
        "inputSchema": {
            "type": "object",
            "properties": {"study_id": {"type": "integer"}, "days": {"type": "integer", "minimum": 1}},
            "additionalProperties": False,
        },
    },
}


def tool_descriptors() -> list[dict]:
    return [
        {
            "name": name,
            "description": meta["description"],
            "inputSchema": meta["inputSchema"],
        }
        for name, meta in READ_ONLY_TOOLS.items()
    ]

