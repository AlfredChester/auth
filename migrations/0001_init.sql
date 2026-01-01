-- Migration number: 0001
CREATE TABLE IF NOT EXISTS product_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value TEXT NOT NULL UNIQUE,
    semver_range TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_product_keys_key_value ON product_keys(key_value);
CREATE INDEX IF NOT EXISTS idx_product_keys_semver_range ON product_keys(semver_range);