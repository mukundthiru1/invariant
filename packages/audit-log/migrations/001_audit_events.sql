CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN ('commit','deploy','approval','block','tamper_detected','rollback')),
  commit_hash TEXT,
  tree_hash TEXT,
  author_email TEXT,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deploy_id TEXT,
  approved_by TEXT,
  customer_id TEXT NOT NULL,
  platform TEXT,
  findings_json TEXT,
  hmac TEXT NOT NULL
);
CREATE INDEX idx_audit_customer ON audit_events(customer_id, ts DESC);
CREATE INDEX idx_audit_commit ON audit_events(commit_hash);
-- NO UPDATE OR DELETE GRANTS — append only enforced at DB level
