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

async fn apply_schema(pool: &DbPool) -> anyhow::Result<()> {
    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    MIGRATOR.run(pool).await?;
    // Pre-migration v0.1 databases may have tables created by the former
    // untracked bootstrapper. Probe those legacy columns explicitly instead
    // of treating every SQL error as proof that a column is absent.
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
    table: &'static str,
    column: &'static str,
    alter_sql: &'static str,
) -> anyhow::Result<()> {
    if !column_exists(pool, table, column).await? {
        sqlx::query(alter_sql).execute(pool).await?;
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
async fn column_exists(pool: &DbPool, table: &str, column: &str) -> anyhow::Result<bool> {
    use sqlx::Row;
    let rows = match table {
        "principals" => {
            sqlx::query("PRAGMA table_info(principals)")
                .fetch_all(pool)
                .await?
        }
        "audit_events" => {
            sqlx::query("PRAGMA table_info(audit_events)")
                .fetch_all(pool)
                .await?
        }
        _ => anyhow::bail!("unsupported legacy schema table '{table}'"),
    };
    for row in rows {
        let name: String = row.try_get("name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "postgres")]
async fn column_exists(pool: &DbPool, table: &str, column: &str) -> anyhow::Result<bool> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
         ) AS present",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await?;
    Ok(row.try_get("present")?)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use sqlx::Row;

    #[tokio::test]
    async fn migrations_install_security_invariants() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        apply_schema(&pool).await.unwrap();
        apply_schema(&pool).await.unwrap();

        let migration_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
        assert_eq!(migration_count, 3);

        let bootstrap_lock_count: i64 =
            sqlx::query("SELECT COUNT(*) AS count FROM bootstrap_lock WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap()
                .try_get("count")
                .unwrap();
        assert_eq!(bootstrap_lock_count, 1);

        sqlx::query(
            "INSERT INTO principals (id, kind, display_name, active, created_at)
             VALUES ('owner', 'human', 'Owner', 1, 'now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO gateways (id, owner_principal_id, hostname, version, last_heartbeat_at)
             VALUES ('gateway', 'owner', 'host', 'test', 'now')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let insert = |id: &'static str, status: &'static str| {
            sqlx::query(
                "INSERT INTO approval_requests
                     (id, gateway_id, server_id, tool_name, args_fingerprint, risk_tier,
                      status, requested_at)
                 VALUES ($1, 'gateway', 'server', 'tool', 'hash', 'require_approval', $2, 'now')",
            )
            .bind(id)
            .bind(status)
        };
        insert("first", "pending").execute(&pool).await.unwrap();
        assert!(insert("duplicate", "pending").execute(&pool).await.is_err());
        sqlx::query(
            "UPDATE approval_requests SET status = 'consumed', used_at = 'now' WHERE id = 'first'",
        )
        .execute(&pool)
        .await
        .unwrap();
        insert("second", "pending").execute(&pool).await.unwrap();
    }
}
