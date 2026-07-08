use sqlx::any::AnyPoolOptions;
use sqlx::AnyPool;

/// VERIFY-AGAINST-DOCS NOTE: sqlx's "Any" driver lets one connection pool and
/// one set of hand-written (not `query!` macro) queries run against either
/// SQLite or Postgres, picked at runtime from the URL scheme
/// (sqlite:./warden.db vs postgres://user:pass@host/db). The tradeoff: you
/// lose sqlx's compile-time query checking. That's the right tradeoff for a
/// v0.1 meant to run unmodified from a laptop to a real Postgres instance -
/// if you want compile-time-checked queries back later, split this into
/// backend-specific pools behind the same repository trait.
pub async fn connect(database_url: &str) -> anyhow::Result<AnyPool> {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    apply_schema(&pool).await?;
    Ok(pool)
}

/// Applies migrations/0001_init.sql directly rather than using sqlx's
/// `migrate!` macro/tracking table - every statement is `CREATE ... IF NOT
/// EXISTS`, so this is idempotent and safe to run on every startup. This is a
/// v0.1 shortcut: once the schema needs real versioned migrations (adding
/// columns to existing tables, backfills), switch to `sqlx-cli` or `refinery`
/// against a concrete backend instead of the Any driver.
async fn apply_schema(pool: &AnyPool) -> anyhow::Result<()> {
    let sql = include_str!("../migrations/0001_init.sql");
    for statement in sql.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        sqlx::query(trimmed).execute(pool).await?;
    }
    Ok(())
}
