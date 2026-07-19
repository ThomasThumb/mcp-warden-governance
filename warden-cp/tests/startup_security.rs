use std::process::Command;

#[test]
fn required_external_signer_fails_before_key_or_database_creation() {
    assert_startup_refuses_local_signer(Some("true"));
}

#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
#[test]
fn postgres_production_build_requires_external_signer_by_default() {
    assert_startup_refuses_local_signer(None);
}

fn assert_startup_refuses_local_signer(require_external: Option<&str>) {
    let directory =
        std::env::temp_dir().join(format!("warden-cp-strict-startup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("temporary test directory should be created");
    let ed25519 = directory.join("ed25519.key");
    let ml_dsa65 = directory.join("ml-dsa65.key");
    let database = directory.join("warden.db");

    let mut command = Command::new(env!("CARGO_BIN_EXE_warden-cp"));
    command
        .current_dir(&directory)
        .env_clear()
        .env("BIND_ADDR", "127.0.0.1:0")
        .env("DATABASE_URL", "sqlite://warden.db?mode=rwc")
        .env("SIGNING_KEY_PATH", &ed25519)
        .env("ML_DSA_SIGNING_KEY_PATH", &ml_dsa65);
    if let Some(value) = require_external {
        command.env("WARDEN_REQUIRE_EXTERNAL_SIGNER", value);
    }
    let output = command.output().expect("warden-cp should execute");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let ed25519_exists = ed25519.exists();
    let ml_dsa65_exists = ml_dsa65.exists();
    let database_exists = database.exists();
    std::fs::remove_dir_all(&directory).expect("temporary test directory should be removed");

    assert!(!output.status.success());
    assert!(stderr.contains("WARDEN_REQUIRE_EXTERNAL_SIGNER=true"));
    assert!(!ed25519_exists);
    assert!(!ml_dsa65_exists);
    assert!(!database_exists);
}
