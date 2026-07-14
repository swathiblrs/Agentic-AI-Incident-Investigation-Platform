CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS security_documents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  content TEXT NOT NULL,
  tags TEXT[] NOT NULL DEFAULT '{}',
  embedding vector(384)
);

CREATE TABLE IF NOT EXISTS investigations (
  id UUID PRIMARY KEY,
  alert_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  report JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS security_documents_embedding_idx
ON security_documents USING ivfflat (embedding vector_cosine_ops);
