from prometheus_client import Counter, Gauge, Histogram

INVESTIGATIONS_TOTAL = Counter(
    "security_investigations_total",
    "Total number of alert investigations executed.",
    ["severity", "verdict"],
)

INVESTIGATION_DURATION = Histogram(
    "security_investigation_duration_seconds",
    "End-to-end investigation duration.",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)

AGENT_DURATION = Histogram(
    "security_agent_duration_seconds",
    "Per-agent execution duration.",
    ["agent"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
)

MCP_TOOL_CALLS_TOTAL = Counter(
    "incident_mcp_tool_calls_total",
    "Total local MCP-style tool calls executed.",
    ["tool", "mode", "status"],
)

MCP_TOOL_DURATION = Histogram(
    "incident_mcp_tool_duration_seconds",
    "Local MCP-style tool execution duration.",
    ["tool", "mode"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
)

A2A_HANDOFFS_TOTAL = Counter(
    "incident_a2a_handoffs_total",
    "Total agent-to-agent style handoffs routed locally.",
    ["source_agent", "target_agent", "domain", "status"],
)

A2A_MESSAGES_TOTAL = Counter(
    "incident_a2a_messages_total",
    "Total structured agent-to-agent task/result messages exchanged locally.",
    ["source_agent", "target_agent", "task_type", "status"],
)

A2A_HANDOFF_DURATION = Histogram(
    "incident_a2a_handoff_duration_seconds",
    "Agent-to-agent style handoff execution duration.",
    ["source_agent", "target_agent", "domain"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
)

DOMAIN_ROUTING_TOTAL = Counter(
    "incident_domain_routing_total",
    "Total incidents routed by domain workflow.",
    ["domain", "target_agent"],
)

EVIDENCE_ITEMS_TOTAL = Counter(
    "incident_evidence_items_total",
    "Total evidence items collected by domain.",
    ["domain", "kind"],
)

AUTOMATED_STEPS_TOTAL = Counter(
    "incident_automated_steps_total",
    "Total incident-response steps automated by the platform.",
    ["domain", "step"],
)

ACTIVE_AGENT_CAPABILITIES = Gauge(
    "incident_active_agent_capabilities",
    "Number of advertised local A2A agent capabilities.",
    ["agent", "domain"],
)

MCP_TOOLS_AVAILABLE = Gauge(
    "incident_mcp_tools_available",
    "Number of MCP-style tools available by mode.",
    ["mode"],
)
