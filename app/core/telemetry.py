from prometheus_client import Counter, Histogram

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
