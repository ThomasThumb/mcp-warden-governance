-- A single well-known row provides a cross-backend write lock while the
-- first root principal and API key are created. This prevents concurrent
-- service starts from minting multiple independent bootstrap credentials.
CREATE TABLE IF NOT EXISTS bootstrap_lock (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    touched_at TEXT NOT NULL
);

INSERT INTO bootstrap_lock (id, touched_at)
VALUES (1, '1970-01-01T00:00:00Z')
ON CONFLICT(id) DO NOTHING;
