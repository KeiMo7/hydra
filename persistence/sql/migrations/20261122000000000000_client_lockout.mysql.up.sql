-- Tracks failed OAuth 2.0 client credential verifications and lockout state
-- with backoff. No foreign key on client_id: attempts against unknown client
-- identifiers must be countable as well, and no credential material is ever
-- stored here.
CREATE TABLE IF NOT EXISTS hydra_client_lockout
(
  client_id         VARCHAR(255) NOT NULL,
  source_hash       VARCHAR(64)  NOT NULL DEFAULT '',
  failure_count     INT          NOT NULL DEFAULT 0,
  window_started_at TIMESTAMP    NOT NULL,
  locked_until      TIMESTAMP    NULL,
  lockout_round     INT          NOT NULL DEFAULT 0,
  created_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
  nid               CHAR(36)     NOT NULL,

  FOREIGN KEY (nid) REFERENCES networks (id) ON UPDATE RESTRICT ON DELETE CASCADE,
  PRIMARY KEY (nid, client_id, source_hash)
);

CREATE INDEX hydra_client_lockout_client_id_idx ON hydra_client_lockout (nid, client_id);

-- Audit trail for operator actions (e.g. manual unlock) on the lockout state.
CREATE TABLE IF NOT EXISTS hydra_client_lockout_audit
(
  id         VARCHAR(36)  NOT NULL,
  nid        CHAR(36)     NOT NULL,
  client_id  VARCHAR(255) NOT NULL,
  action     VARCHAR(32)  NOT NULL,
  actor      VARCHAR(255) NOT NULL DEFAULT '',
  created_at TIMESTAMP    NOT NULL DEFAULT NOW(),

  FOREIGN KEY (nid) REFERENCES networks (id) ON UPDATE RESTRICT ON DELETE CASCADE,
  PRIMARY KEY (id, nid)
);

CREATE INDEX hydra_client_lockout_audit_client_id_idx ON hydra_client_lockout_audit (nid, client_id);
