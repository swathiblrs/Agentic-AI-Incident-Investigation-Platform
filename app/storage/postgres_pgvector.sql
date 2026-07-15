CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS security_documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  content TEXT NOT NULL,
  tags TEXT[] NOT NULL DEFAULT '{}',
  domain TEXT,
  team TEXT,
  service TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  embedding vector(384)
);

CREATE TABLE IF NOT EXISTS investigations (
  id UUID PRIMARY KEY,
  alert_id TEXT,
  incident_id TEXT,
  domain TEXT NOT NULL DEFAULT 'security',
  verdict TEXT,
  status TEXT,
  risk_score INTEGER NOT NULL,
  session_id TEXT,
  report JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS session_messages (
  id BIGSERIAL PRIMARY KEY,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS security_documents_embedding_idx
ON security_documents USING ivfflat (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS security_documents_domain_idx
ON security_documents (domain, service, team, created_at);

CREATE INDEX IF NOT EXISTS session_messages_session_id_idx
ON session_messages (session_id, created_at);
