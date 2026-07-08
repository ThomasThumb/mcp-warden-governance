#[cfg(all(feature = "sqlite", feature = "postgres"))]
compile_error!("Enable exactly one warden-cp storage backend: sqlite or postgres.");

#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("Enable exactly one warden-cp storage backend: sqlite or postgres.");

#[cfg(feature = "postgres")]
pub type DbPool = sqlx::PgPool;

#[cfg(feature = "postgres")]
pub type DbRow = sqlx::postgres::PgRow;

#[cfg(feature = "sqlite")]
pub type DbPool = sqlx::SqlitePool;

#[cfg(feature = "sqlite")]
pub type DbRow = sqlx::sqlite::SqliteRow;

pub async fn connect(database_url: &str) -> anyhow::Result<DbPool> {
    let pool = connect_backend(database_url).await?;
    apply_schema(&pool).await?;
    Ok(pool)
}

#[cfg(feature = "postgres")]
async fn connect_backend(database_url: &str) -> anyhow::Result<DbPool> {
    if !database_url.starts_with("postgres://") && !database_url.starts_with("postgresql://") {
        anyhow::bail!(
            "this warden-cp binary was built with the postgres feature; DATABASE_URL must start with postgres:// or postgresql://"
        );
    }

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(Into::into)
}

#[cfg(feature = "sqlite")]
async fn connect_backend(database_url: &str) -> anyhow::Result<DbPool> {
    if !database_url.starts_with("sqlite://") {
        anyhow::bail!(
            "this warden-cp binary was built with the sqlite feature; DATABASE_URL must start with sqlite://"
        );
    }

    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(Into::into)
}

/// Applies migrations/0001_init.sql directly rather than using sqlx's
/// `migrate!` macro/tracking table - every statement is `CREATE ... IF NOT
/// EXISTS`, so this is idempotent and safe to run on every startup. The
/// selected backend is compile-time explicit, which keeps the lockfile from
/// resolving unused SQLx drivers and makes dependency audit output meaningful.
async fn apply_schema(pool: &DbPool) -> anyhow::Result<()> {
    let sql = include_str!("../migrations/0001_init.sql");
    for statement in sql.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        sqlx::query(trimmed).execute(pool).await?;
    }
    ensure_columns(pool).await?;
    ensure_indexes(pool).await?;
    Ok(())
}

async fn ensure_columns(pool: &DbPool) -> anyhow::Result<()> {
    ensure_column(
        pool,
        "principals",
        "active",
        "ALTER TABLE principals ADD COLUMN active BIGINT NOT NULL DEFAULT 1",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "seq",
        "ALTER TABLE audit_events ADD COLUMN seq BIGINT",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "canonical_version",
        "ALTER TABLE audit_events ADD COLUMN canonical_version BIGINT NOT NULL DEFAULT 1",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "checkpoint_signed_at",
        "ALTER TABLE audit_events ADD COLUMN checkpoint_signed_at TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "checkpoint_sig_b64",
        "ALTER TABLE audit_events ADD COLUMN checkpoint_sig_b64 TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "checkpoint_ml_dsa_alg",
        "ALTER TABLE audit_events ADD COLUMN checkpoint_ml_dsa_alg TEXT",
    )
    .await?;
    ensure_column(
        pool,
        "audit_events",
        "checkpoint_ml_dsa_sig_b64",
        "ALTER TABLE audit_events ADD COLUMN checkpoint_ml_dsa_sig_b64 TEXT",
    )
    .await?;

    Ok(())
}

async fn ensure_indexes(pool: &DbPool) -> anyhow::Result<()> {
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(seq)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_issued_tokens_session ON issued_tokens(agent_session_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn ensure_column(
    pool: &DbPool,
    table: &str,
    column: &str,
    alter_sql: &str,
) -> anyhow::Result<()> {
    let probe = format!("SELECT {column} FROM {table} LIMIT 1");
    if sqlx::query(&probe).execute(pool).await.is_err() {
        sqlx::query(alter_sql).execute(pool).await?;
    }
    Ok(())
}
