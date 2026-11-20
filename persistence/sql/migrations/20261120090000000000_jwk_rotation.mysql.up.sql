CREATE TABLE hydra_jwk_rotation
(
    pk             CHAR(36)     NOT NULL PRIMARY KEY,
    nid            CHAR(36)     NOT NULL,
    sid            VARCHAR(255) NOT NULL,
    kid            VARCHAR(255) NOT NULL,
    state          VARCHAR(20)  NOT NULL,
    generation     BIGINT       NOT NULL DEFAULT 1,
    activated_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleanup_after  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tombstoned_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE,
    UNIQUE KEY hydra_jwk_rotation_nid_sid_kid_idx (nid, sid, kid),
    KEY hydra_jwk_rotation_nid_sid_state_idx (nid, sid, state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
