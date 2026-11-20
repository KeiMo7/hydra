CREATE TABLE IF NOT EXISTS hydra_jwk_rotation
(
    pk             UUID         NOT NULL PRIMARY KEY,
    nid            UUID         NOT NULL,
    sid            VARCHAR(255) NOT NULL,
    kid            VARCHAR(255) NOT NULL,
    state          VARCHAR(20)  NOT NULL,
    generation     BIGINT       NOT NULL DEFAULT 1,
    activated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleanup_after  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tombstoned_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS hydra_jwk_rotation_nid_sid_kid_idx ON hydra_jwk_rotation (nid, sid, kid);
CREATE INDEX IF NOT EXISTS hydra_jwk_rotation_nid_sid_state_idx ON hydra_jwk_rotation (nid, sid, state);
