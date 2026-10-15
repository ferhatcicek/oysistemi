-- OySistemi şeması.
-- KURAL: Bu dosya değiştiğinde çalışan veritabanının şema parmak izi de değişir;
-- verifier, diskteki şemayı bu dosyadan üretilen şemayla karşılaştırır.

-- Uygulamanın her meşru değişiklikten önce doldurduğu denetim bağlamı (tek satır).
-- Tetikleyiciler buradaki audit_seq'i shadow_log'a kopyalar; NULL = bant dışı değişiklik.
CREATE TABLE _ctx (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    audit_seq INTEGER
) STRICT;
INSERT INTO _ctx (id, audit_seq) VALUES (1, NULL);

-- ───────────────────────── KİMLİK TARAFI ─────────────────────────
CREATE TABLE voters (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email        TEXT,
    status       TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at   TEXT NOT NULL,
    row_mac      BLOB NOT NULL
) STRICT;

CREATE TABLE admins (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    pw_hash         TEXT NOT NULL,
    totp_secret_enc BLOB,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'auditor')),
    created_at      TEXT NOT NULL,
    row_mac         BLOB NOT NULL
) STRICT;

CREATE TABLE elections (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    ballot_type     TEXT NOT NULL,
    config          TEXT NOT NULL,
    config_hash     TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('draft', 'open', 'closed', 'tallied', 'archived')),
    roll_hash       TEXT,
    pubkey_pem      BLOB,
    privkey_wrapped BLOB,
    result          TEXT,
    created_by      TEXT NOT NULL REFERENCES admins (id),
    row_mac         BLOB NOT NULL
) STRICT;

CREATE TABLE election_voters (
    election_id TEXT NOT NULL REFERENCES elections (id),
    voter_id    TEXT NOT NULL REFERENCES voters (id),
    row_mac     BLOB NOT NULL,
    PRIMARY KEY (election_id, voter_id)
) STRICT, WITHOUT ROWID;

-- Seçmen başına en fazla BİR kör imza (çift oy engelinin 1. katmanı).
-- Zaman damgası bilinçli olarak yok.
CREATE TABLE credential_issuance (
    election_id TEXT NOT NULL,
    voter_id    TEXT NOT NULL,
    blinded_msg BLOB NOT NULL,
    blind_sig   BLOB NOT NULL,
    PRIMARY KEY (election_id, voter_id),
    FOREIGN KEY (election_id, voter_id) REFERENCES election_voters (election_id, voter_id)
) STRICT, WITHOUT ROWID;

-- Seçmen giriş kodları (basılı kod / e-posta OTP). Yalnızca argon2 hash'i saklanır.
CREATE TABLE auth_codes (
    election_id TEXT NOT NULL REFERENCES elections (id),
    voter_id    TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN ('printed_code', 'email_otp')),
    code_hash   TEXT NOT NULL,
    expires_at  TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
    row_mac     BLOB NOT NULL,
    PRIMARY KEY (election_id, voter_id, method),
    FOREIGN KEY (election_id, voter_id) REFERENCES election_voters (election_id, voter_id)
) STRICT, WITHOUT ROWID;

-- ───────────────────────── SANDIK TARAFI ─────────────────────────
-- voter_id, zaman damgası, IP YOK. WITHOUT ROWID → fiziksel sıra token_hash'e göre,
-- ekleme sırası sızmaz. Bir imza = bir oy (çift oy engelinin 2. katmanı).
CREATE TABLE ballots (
    election_id TEXT NOT NULL REFERENCES elections (id),
    token_hash  BLOB NOT NULL,
    token       BLOB NOT NULL,
    sig         BLOB NOT NULL,
    ballot      TEXT NOT NULL,
    PRIMARY KEY (election_id, token_hash)
) STRICT, WITHOUT ROWID;

-- ───────────────────────── YÖNETİŞİM ─────────────────────────
CREATE TABLE change_requests (
    id                 TEXT PRIMARY KEY,
    kind               TEXT NOT NULL,
    payload            TEXT NOT NULL,
    proposed_by        TEXT NOT NULL REFERENCES admins (id),
    status             TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'rejected')),
    required_approvals INTEGER NOT NULL CHECK (required_approvals >= 1),
    created_at         TEXT NOT NULL,
    row_mac            BLOB NOT NULL
) STRICT;

CREATE TABLE approvals (
    request_id TEXT NOT NULL REFERENCES change_requests (id),
    admin_id   TEXT NOT NULL REFERENCES admins (id),
    decision   TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    ts         TEXT NOT NULL,
    PRIMARY KEY (request_id, admin_id)
) STRICT;

-- ───────────────────────── AYAK İZİ ─────────────────────────
CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    entry_mac  TEXT NOT NULL
) STRICT;

-- Seçmen olayları (giriş, oy hakkı alma) oylama başına AYRI bir hash zincirinde tutulur.
-- Ana denetim zincirinde olsalardı, sıra numarası boşlukları ve checkpoint'lerdeki audit_seq
-- farkı oylama sürerken katılımı ele verirdi. Kapanışta bu zincirin başı ana zincire mühürlenir.
CREATE TABLE voter_log (
    election_id TEXT NOT NULL REFERENCES elections (id),
    seq         INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    voter_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    payload     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    entry_mac   TEXT NOT NULL,
    PRIMARY KEY (election_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE shadow_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    tbl       TEXT NOT NULL,
    op        TEXT NOT NULL,
    row_key   TEXT NOT NULL,
    audit_seq INTEGER
) STRICT;

CREATE TABLE checkpoints (
    seq        INTEGER PRIMARY KEY,
    audit_seq  INTEGER NOT NULL,
    body       TEXT NOT NULL,
    mac        TEXT NOT NULL
) STRICT;

-- Denetim kaydı zamanı asla geriye gitmez (saat geri alınarak geriye tarihli kayıt yazılamaz).
CREATE TRIGGER audit_log_monotonic_ts BEFORE INSERT ON audit_log
WHEN NEW.ts < (SELECT MAX(ts) FROM audit_log)
BEGIN SELECT RAISE(ABORT, 'audit timestamp went backwards (clock rollback?)'); END;

CREATE TRIGGER voter_log_monotonic_ts BEFORE INSERT ON voter_log
WHEN NEW.ts < (SELECT MAX(ts) FROM voter_log WHERE election_id = NEW.election_id)
BEGIN SELECT RAISE(ABORT, 'voter log timestamp went backwards (clock rollback?)'); END;
CREATE TRIGGER voter_log_no_update BEFORE UPDATE ON voter_log
BEGIN SELECT RAISE(ABORT, 'voter_log is append-only'); END;
CREATE TRIGGER voter_log_no_delete BEFORE DELETE ON voter_log
BEGIN SELECT RAISE(ABORT, 'voter_log is append-only'); END;

-- ───────────────────── Salt-ekleme (append-only) tetikleyicileri ─────────────────────
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER shadow_log_no_update BEFORE UPDATE ON shadow_log
BEGIN SELECT RAISE(ABORT, 'shadow_log is append-only'); END;
CREATE TRIGGER shadow_log_no_delete BEFORE DELETE ON shadow_log
BEGIN SELECT RAISE(ABORT, 'shadow_log is append-only'); END;
CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals
BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END;
CREATE TRIGGER checkpoints_no_update BEFORE UPDATE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;
CREATE TRIGGER checkpoints_no_delete BEFORE DELETE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END;

-- Seçmenler hiçbir zaman silinmez, yalnızca 'disabled' yapılır (iz kaybolmasın).
CREATE TRIGGER voters_no_delete BEFORE DELETE ON voters
BEGIN SELECT RAISE(ABORT, 'voters cannot be deleted; disable instead'); END;
CREATE TRIGGER admins_no_delete BEFORE DELETE ON admins
BEGIN SELECT RAISE(ABORT, 'admins cannot be deleted'); END;
CREATE TRIGGER elections_no_delete BEFORE DELETE ON elections
BEGIN SELECT RAISE(ABORT, 'elections cannot be deleted'); END;

-- ───────────────────── Seçim durum makinesi ─────────────────────
CREATE TRIGGER elections_status_flow BEFORE UPDATE OF status ON elections
WHEN NEW.status <> OLD.status AND NOT (
       (OLD.status = 'draft'   AND NEW.status = 'open')
    OR (OLD.status = 'open'    AND NEW.status = 'closed')
    OR (OLD.status = 'closed'  AND NEW.status = 'tallied')
    OR (OLD.status = 'tallied' AND NEW.status = 'archived'))
BEGIN SELECT RAISE(ABORT, 'illegal election status transition'); END;

CREATE TRIGGER elections_config_frozen BEFORE UPDATE OF title, ballot_type, config ON elections
WHEN OLD.status <> 'draft'
BEGIN SELECT RAISE(ABORT, 'election config is frozen'); END;

CREATE TRIGGER elections_seal_frozen BEFORE UPDATE OF config_hash, roll_hash, pubkey_pem ON elections
WHEN OLD.status <> 'draft'
BEGIN SELECT RAISE(ABORT, 'election seal is frozen'); END;

-- Silinen özel anahtar geri yüklenemez.
CREATE TRIGGER elections_key_destroyed BEFORE UPDATE OF privkey_wrapped ON elections
WHEN OLD.status <> 'draft' AND OLD.privkey_wrapped IS NULL AND NEW.privkey_wrapped IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'destroyed election key cannot be restored'); END;

-- ───────────────────── Seçmen listesi dondurma ─────────────────────
CREATE TRIGGER election_voters_frozen_ins BEFORE INSERT ON election_voters
WHEN (SELECT status FROM elections WHERE id = NEW.election_id) <> 'draft'
BEGIN SELECT RAISE(ABORT, 'voter roll is frozen'); END;
CREATE TRIGGER election_voters_frozen_del BEFORE DELETE ON election_voters
WHEN (SELECT status FROM elections WHERE id = OLD.election_id) <> 'draft'
BEGIN SELECT RAISE(ABORT, 'voter roll is frozen'); END;
CREATE TRIGGER election_voters_no_update BEFORE UPDATE ON election_voters
BEGIN SELECT RAISE(ABORT, 'voter roll rows are immutable'); END;

-- ───────────────────── Kimlik bilgisi ve sandık ─────────────────────
CREATE TRIGGER issuance_only_open BEFORE INSERT ON credential_issuance
WHEN (SELECT status FROM elections WHERE id = NEW.election_id) <> 'open'
BEGIN SELECT RAISE(ABORT, 'election is not open'); END;
CREATE TRIGGER issuance_no_update BEFORE UPDATE ON credential_issuance
BEGIN SELECT RAISE(ABORT, 'issuance is immutable'); END;
CREATE TRIGGER issuance_no_delete BEFORE DELETE ON credential_issuance
BEGIN SELECT RAISE(ABORT, 'issuance is immutable'); END;

CREATE TRIGGER ballots_only_open BEFORE INSERT ON ballots
WHEN (SELECT status FROM elections WHERE id = NEW.election_id) <> 'open'
BEGIN SELECT RAISE(ABORT, 'election is not open'); END;
CREATE TRIGGER ballots_no_update BEFORE UPDATE ON ballots
BEGIN SELECT RAISE(ABORT, 'ballots are immutable'); END;
CREATE TRIGGER ballots_no_delete BEFORE DELETE ON ballots
BEGIN SELECT RAISE(ABORT, 'ballots are immutable'); END;

-- ───────────────────── Gölge log (ayak izi) ─────────────────────
-- ballots ve credential_issuance BİLİNÇLİ OLARAK gölge loglanmaz: sıra/zaman bilgisi
-- oy–seçmen bağlantısı için yan kanal olur.
CREATE TRIGGER voters_shadow_ins AFTER INSERT ON voters
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('voters', 'INSERT', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
CREATE TRIGGER voters_shadow_upd AFTER UPDATE ON voters
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('voters', 'UPDATE', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;

CREATE TRIGGER admins_shadow_ins AFTER INSERT ON admins
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('admins', 'INSERT', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
CREATE TRIGGER admins_shadow_upd AFTER UPDATE ON admins
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('admins', 'UPDATE', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;

CREATE TRIGGER elections_shadow_ins AFTER INSERT ON elections
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('elections', 'INSERT', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
CREATE TRIGGER elections_shadow_upd AFTER UPDATE ON elections
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('elections', 'UPDATE', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;

CREATE TRIGGER election_voters_shadow_ins AFTER INSERT ON election_voters
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('election_voters', 'INSERT', NEW.election_id || '/' || NEW.voter_id,
              (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
CREATE TRIGGER election_voters_shadow_del AFTER DELETE ON election_voters
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('election_voters', 'DELETE', OLD.election_id || '/' || OLD.voter_id,
              (SELECT audit_seq FROM _ctx WHERE id = 1)); END;

CREATE TRIGGER change_requests_shadow_ins AFTER INSERT ON change_requests
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('change_requests', 'INSERT', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
CREATE TRIGGER change_requests_shadow_upd AFTER UPDATE ON change_requests
BEGIN INSERT INTO shadow_log (tbl, op, row_key, audit_seq)
      VALUES ('change_requests', 'UPDATE', NEW.id, (SELECT audit_seq FROM _ctx WHERE id = 1)); END;
