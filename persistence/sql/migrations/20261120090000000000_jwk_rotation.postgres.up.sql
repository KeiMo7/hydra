CREATE TABLE hydra_jwk_rotation
(
    pk             UUID         NOT NULL PRIMARY KEY,
    nid            UUID         NOT NULL,
    sid            VARCHAR(255) NOT NULL,
    kid            VARCHAR(255) NOT NULL,
    state          VARCHAR(20)  NOT NULL,
    generation     BIGINT       NOT NULL DEFAULT 1,
    activated_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    retired_at     TIMESTAMP    NOT NULL DEFAULT NOW(),
    cleanup_after  TIMESTAMP    NOT NULL DEFAULT NOW(),
    tombstoned_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP    NOT NULL DEFAULT NOW(),
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX hydra_jwk_rotation_nid_sid_kid_idx ON hydra_jwk_rotation (nid, sid, kid);
CREATE INDEX hydra_jwk_rotation_nid_sid_state_idx ON hydra_jwk_rotation (nid, sid, state);
