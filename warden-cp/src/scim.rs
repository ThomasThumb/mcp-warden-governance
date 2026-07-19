use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::auth::AuthedPrincipal;
use crate::db::DbRow;
use crate::routes::AppState;

type ApiResult<T> = Result<T, (StatusCode, String)>;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimUserIn {
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    pub active: Option<bool>,
    pub emails: Option<Vec<ScimEmail>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimEmail {
    pub value: String,
    pub primary: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimGroupIn {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    pub members: Option<Vec<ScimMember>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ScimMember {
    pub value: String,
    #[serde(rename = "display")]
    pub display: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRequest {
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Option<Value>,
}

pub async fn service_provider_config() -> Json<Value> {
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer token",
            "description": "Use a warden-cp root_admin or security_admin bearer token."
        }]
    }))
}

pub async fn schemas() -> Json<Value> {
    Json(json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": 2,
        "startIndex": 1,
        "itemsPerPage": 2,
        "Resources": [
            { "id": USER_SCHEMA, "name": "User" },
            { "id": GROUP_SCHEMA, "name": "Group" }
        ]
    }))
}

pub async fn list_users(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    let bind_value = equality_filter(query.filter.as_deref(), "userName")?;
    let limit = query.count.unwrap_or(100).clamp(1, 200);
    let offset = query.start_index.unwrap_or(1).max(1) - 1;
    let rows = if let Some(value) = bind_value {
        sqlx::query(
            "SELECT id, display_name, external_id, active, created_at FROM principals
             WHERE kind = 'human'
               AND id IN (
                   SELECT principal_id FROM principal_identities
                   WHERE provider = 'scim' AND external_subject = $1
               )
             ORDER BY display_name LIMIT $2 OFFSET $3",
        )
        .bind(value)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, display_name, external_id, active, created_at FROM principals
             WHERE kind = 'human'
             ORDER BY display_name LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;
    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        resources.push(user_json(&state, &row).await?);
    }
    Ok(Json(list_response(resources, offset + 1, limit)))
}

pub async fn create_user(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<ScimUserIn>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    ensure_scim_admin(&state, &principal).await?;
    let id = upsert_user(&state, req).await?;
    let row = principal_row(&state, &id).await?;
    Ok((StatusCode::CREATED, Json(user_json(&state, &row).await?)))
}

pub async fn get_user(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    let row = principal_row(&state, &id).await?;
    Ok(Json(user_json(&state, &row).await?))
}

pub async fn replace_user(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<ScimUserIn>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    ensure_principal(&state, &id).await?;
    update_user(&state, &id, &req).await?;
    if req.active == Some(false) {
        deactivate_principal(&state, &id).await?;
    }
    let row = principal_row(&state, &id).await?;
    Ok(Json(user_json(&state, &row).await?))
}

pub async fn patch_user(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    ensure_principal(&state, &id).await?;
    if req.operations.len() > 100 {
        return Err(bad_request("SCIM patch may contain at most 100 operations"));
    }
    for op in req.operations {
        if !matches!(op.op.to_ascii_lowercase().as_str(), "add" | "replace") {
            return Err(bad_request("unsupported SCIM user patch operation"));
        }
        let path = op.path.unwrap_or_default().to_ascii_lowercase();
        if path == "active" {
            if op.value == Some(Value::Bool(false)) {
                deactivate_principal(&state, &id).await?;
            } else if op.value == Some(Value::Bool(true)) {
                sqlx::query("UPDATE principals SET active = 1 WHERE id = $1")
                    .bind(&id)
                    .execute(&state.pool)
                    .await
                    .map_err(err500)?;
            }
        } else if path == "displayname" || path == "username" {
            if let Some(Value::String(value)) = op.value {
                validate_scim_text("SCIM display name", &value, 256)?;
                sqlx::query("UPDATE principals SET display_name = $1 WHERE id = $2")
                    .bind(value)
                    .bind(&id)
                    .execute(&state.pool)
                    .await
                    .map_err(err500)?;
            } else {
                return Err(bad_request(
                    "SCIM display name patch requires a string value",
                ));
            }
        } else {
            return Err(bad_request("unsupported SCIM user patch path"));
        }
    }
    let row = principal_row(&state, &id).await?;
    Ok(Json(user_json(&state, &row).await?))
}

pub async fn delete_user(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    ensure_scim_admin(&state, &principal).await?;
    ensure_principal(&state, &id).await?;
    deactivate_principal(&state, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_groups(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    let bind_value = equality_filter(query.filter.as_deref(), "displayName")?;
    let limit = query.count.unwrap_or(100).clamp(1, 200);
    let offset = query.start_index.unwrap_or(1).max(1) - 1;
    let rows = if let Some(value) = bind_value {
        sqlx::query(
            "SELECT id, display_name, external_id, active, created_at FROM groups
             WHERE active = 1 AND display_name = $1
             ORDER BY display_name LIMIT $2 OFFSET $3",
        )
        .bind(value)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query(
            "SELECT id, display_name, external_id, active, created_at FROM groups
             WHERE active = 1
             ORDER BY display_name LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
    }
    .map_err(err500)?;
    let mut resources = Vec::with_capacity(rows.len());
    for row in rows {
        resources.push(group_json(&state, &row).await?);
    }
    Ok(Json(list_response(resources, offset + 1, limit)))
}

pub async fn create_group(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Json(req): Json<ScimGroupIn>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    ensure_scim_admin(&state, &principal).await?;
    let id = upsert_group(&state, req).await?;
    let row = group_row(&state, &id).await?;
    Ok((StatusCode::CREATED, Json(group_json(&state, &row).await?)))
}

pub async fn get_group(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    let row = group_row(&state, &id).await?;
    Ok(Json(group_json(&state, &row).await?))
}

pub async fn replace_group(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<ScimGroupIn>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    ensure_group(&state, &id).await?;
    update_group(&state, &id, &req).await?;
    replace_members(&state, &id, req.members.as_deref()).await?;
    let row = group_row(&state, &id).await?;
    Ok(Json(group_json(&state, &row).await?))
}

pub async fn patch_group(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
    Json(req): Json<PatchRequest>,
) -> ApiResult<Json<Value>> {
    ensure_scim_admin(&state, &principal).await?;
    ensure_group(&state, &id).await?;
    if req.operations.len() > 100 {
        return Err(bad_request("SCIM patch may contain at most 100 operations"));
    }
    for op in req.operations {
        let op_name = op.op.to_ascii_lowercase();
        if !matches!(op_name.as_str(), "add" | "replace" | "remove") {
            return Err(bad_request("unsupported SCIM group patch operation"));
        }
        let path = op.path.unwrap_or_default().to_ascii_lowercase();
        if path == "members" || path.is_empty() {
            apply_member_patch(&state, &id, &op_name, op.value).await?;
        } else if path == "displayname" {
            if let Some(Value::String(value)) = op.value {
                validate_scim_text("SCIM group display name", &value, 256)?;
                sqlx::query("UPDATE groups SET display_name = $1 WHERE id = $2")
                    .bind(value)
                    .bind(&id)
                    .execute(&state.pool)
                    .await
                    .map_err(err500)?;
            } else {
                return Err(bad_request(
                    "SCIM group display name patch requires a string value",
                ));
            }
        } else {
            return Err(bad_request("unsupported SCIM group patch path"));
        }
    }
    let row = group_row(&state, &id).await?;
    Ok(Json(group_json(&state, &row).await?))
}

pub async fn delete_group(
    State(state): State<AppState>,
    principal: AuthedPrincipal,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    ensure_scim_admin(&state, &principal).await?;
    sqlx::query("UPDATE groups SET active = 0 WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    sqlx::query("DELETE FROM group_members WHERE group_id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn ensure_scim_admin(state: &AppState, principal: &AuthedPrincipal) -> ApiResult<()> {
    let row = sqlx::query(
        "SELECT 1 FROM principal_roles
         WHERE principal_id = $1 AND role IN ('root_admin', 'security_admin')
         UNION
         SELECT 1 FROM group_members
         JOIN groups ON groups.id = group_members.group_id
         JOIN group_roles ON group_roles.group_id = group_members.group_id
         WHERE group_members.principal_id = $2
           AND groups.active = 1
           AND group_roles.role IN ('root_admin', 'security_admin')
         LIMIT 1",
    )
    .bind(&principal.0)
    .bind(&principal.0)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;
    if row.is_some() {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "SCIM admin role required".into()))
    }
}

async fn upsert_user(state: &AppState, req: ScimUserIn) -> ApiResult<String> {
    validate_scim_user(&req)?;
    let subject = req
        .external_id
        .clone()
        .unwrap_or_else(|| req.user_name.clone());
    if let Some(row) = sqlx::query(
        "SELECT principal_id FROM principal_identities
         WHERE provider = 'scim' AND external_subject = $1",
    )
    .bind(&subject)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    {
        let id: String = row.try_get("principal_id").map_err(err500)?;
        update_user(state, &id, &req).await?;
        if req.active == Some(false) {
            deactivate_principal(state, &id).await?;
        }
        return Ok(id);
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let display = req
        .display_name
        .clone()
        .unwrap_or_else(|| req.user_name.clone());
    sqlx::query(
        "INSERT INTO principals (id, kind, display_name, external_id, active, created_at)
         VALUES ($1, 'human', $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(display)
    .bind(format!("scim:{subject}"))
    .bind(if req.active.unwrap_or(true) { 1 } else { 0 })
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    sqlx::query(
        "INSERT INTO principal_identities
             (provider, external_subject, principal_id, email, created_at, updated_at)
         VALUES ('scim', $1, $2, $3, $4, $5)",
    )
    .bind(&subject)
    .bind(&id)
    .bind(primary_email(&req))
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    if req.active == Some(false) {
        deactivate_principal(state, &id).await?;
    }
    Ok(id)
}

async fn update_user(state: &AppState, id: &str, req: &ScimUserIn) -> ApiResult<()> {
    validate_scim_user(req)?;
    let display = req
        .display_name
        .clone()
        .unwrap_or_else(|| req.user_name.clone());
    sqlx::query("UPDATE principals SET display_name = $1, active = $2 WHERE id = $3")
        .bind(display)
        .bind(if req.active.unwrap_or(true) { 1 } else { 0 })
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    sqlx::query(
        "UPDATE principal_identities SET email = $1, updated_at = $2
         WHERE provider = 'scim' AND principal_id = $3",
    )
    .bind(primary_email(req))
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok(())
}

async fn upsert_group(state: &AppState, req: ScimGroupIn) -> ApiResult<String> {
    validate_scim_group(&req)?;
    let external = req
        .external_id
        .clone()
        .unwrap_or_else(|| req.display_name.clone());
    if let Some(row) = sqlx::query("SELECT id FROM groups WHERE external_id = $1")
        .bind(format!("scim:{external}"))
        .fetch_optional(&state.pool)
        .await
        .map_err(err500)?
    {
        let id: String = row.try_get("id").map_err(err500)?;
        update_group(state, &id, &req).await?;
        replace_members(state, &id, req.members.as_deref()).await?;
        return Ok(id);
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO groups (id, display_name, external_id, active, created_at)
         VALUES ($1, $2, $3, 1, $4)",
    )
    .bind(&id)
    .bind(&req.display_name)
    .bind(format!("scim:{external}"))
    .bind(Utc::now().to_rfc3339())
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    replace_members(state, &id, req.members.as_deref()).await?;
    Ok(id)
}

async fn update_group(state: &AppState, id: &str, req: &ScimGroupIn) -> ApiResult<()> {
    validate_scim_group(req)?;
    sqlx::query("UPDATE groups SET display_name = $1, active = 1 WHERE id = $2")
        .bind(&req.display_name)
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    Ok(())
}

async fn replace_members(
    state: &AppState,
    group_id: &str,
    members: Option<&[ScimMember]>,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM group_members WHERE group_id = $1")
        .bind(group_id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    let Some(members) = members else {
        return Ok(());
    };
    for member in members {
        ensure_principal(state, &member.value).await?;
        add_member(state, group_id, &member.value).await?;
    }
    Ok(())
}

async fn apply_member_patch(
    state: &AppState,
    group_id: &str,
    op: &str,
    value: Option<Value>,
) -> ApiResult<()> {
    let members = parse_members(value)?;
    if members.len() > 500 {
        return Err(bad_request(
            "a SCIM group patch may contain at most 500 members",
        ));
    }
    for member in &members {
        validate_scim_text("SCIM member id", &member.value, 128)?;
    }
    match op {
        "add" | "replace" => {
            if op == "replace" {
                sqlx::query("DELETE FROM group_members WHERE group_id = $1")
                    .bind(group_id)
                    .execute(&state.pool)
                    .await
                    .map_err(err500)?;
            }
            for member in members {
                ensure_principal(state, &member.value).await?;
                add_member(state, group_id, &member.value).await?;
            }
        }
        "remove" => {
            for member in members {
                sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND principal_id = $2")
                    .bind(group_id)
                    .bind(member.value)
                    .execute(&state.pool)
                    .await
                    .map_err(err500)?;
            }
        }
        _ => return Err((StatusCode::BAD_REQUEST, "unsupported SCIM patch op".into())),
    }
    Ok(())
}

fn parse_members(value: Option<Value>) -> ApiResult<Vec<ScimMember>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Some(members) = value.get("members") {
        return serde_json::from_value(members.clone()).map_err(bad_request);
    }
    if value.is_array() {
        return serde_json::from_value(value).map_err(bad_request);
    }
    serde_json::from_value(value)
        .map(|member| vec![member])
        .map_err(bad_request)
}

async fn add_member(state: &AppState, group_id: &str, principal_id: &str) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO group_members (group_id, principal_id)
         VALUES ($1, $2) ON CONFLICT(group_id, principal_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(principal_id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok(())
}

async fn deactivate_principal(state: &AppState, id: &str) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE principals SET active = 0 WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(err500)?;
    sqlx::query(
        "UPDATE api_keys SET revoked_at = $1 WHERE principal_id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = $1 WHERE principal_id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    sqlx::query(
        "UPDATE agent_sessions SET revoked_at = $1 WHERE principal_id = $2 AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(err500)?;
    Ok(())
}

async fn principal_row(state: &AppState, id: &str) -> ApiResult<DbRow> {
    sqlx::query(
        "SELECT id, display_name, external_id, active, created_at FROM principals WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    .ok_or((StatusCode::NOT_FOUND, "SCIM user not found".into()))
}

async fn group_row(state: &AppState, id: &str) -> ApiResult<DbRow> {
    sqlx::query(
        "SELECT id, display_name, external_id, active, created_at FROM groups WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?
    .ok_or((StatusCode::NOT_FOUND, "SCIM group not found".into()))
}

async fn ensure_principal(state: &AppState, id: &str) -> ApiResult<()> {
    principal_row(state, id).await.map(|_| ())
}

async fn ensure_group(state: &AppState, id: &str) -> ApiResult<()> {
    group_row(state, id).await.map(|_| ())
}

async fn user_json(state: &AppState, row: &DbRow) -> ApiResult<Value> {
    let id: String = row.try_get("id").map_err(err500)?;
    let identities = sqlx::query(
        "SELECT external_subject, email FROM principal_identities
         WHERE provider = 'scim' AND principal_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(err500)?;
    let user_name = identities
        .as_ref()
        .map(|r| r.try_get::<String, _>("external_subject").map_err(err500))
        .transpose()?
        .unwrap_or_else(|| id.clone());
    let email = identities
        .map(|r| r.try_get::<Option<String>, _>("email").map_err(err500))
        .transpose()?
        .flatten();
    Ok(json!({
        "schemas": [USER_SCHEMA],
        "id": id,
        "userName": user_name,
        "displayName": row.try_get::<String, _>("display_name").map_err(err500)?,
        "externalId": row.try_get::<Option<String>, _>("external_id").map_err(err500)?,
        "active": row.try_get::<i64, _>("active").map_err(err500)? != 0,
        "emails": email.map(|value| vec![json!({"value": value, "primary": true})]).unwrap_or_default(),
        "meta": { "resourceType": "User", "created": row.try_get::<String, _>("created_at").map_err(err500)? }
    }))
}

async fn group_json(state: &AppState, row: &DbRow) -> ApiResult<Value> {
    let id: String = row.try_get("id").map_err(err500)?;
    let member_rows = sqlx::query(
        "SELECT principals.id, principals.display_name
         FROM group_members
         JOIN principals ON principals.id = group_members.principal_id
         WHERE group_members.group_id = $1
         ORDER BY principals.display_name",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    .map_err(err500)?;
    let mut members = Vec::with_capacity(member_rows.len());
    for member in member_rows {
        members.push(json!({
            "value": member.try_get::<String, _>("id").map_err(err500)?,
            "display": member.try_get::<String, _>("display_name").map_err(err500)?
        }));
    }
    Ok(json!({
        "schemas": [GROUP_SCHEMA],
        "id": id,
        "displayName": row.try_get::<String, _>("display_name").map_err(err500)?,
        "externalId": row.try_get::<Option<String>, _>("external_id").map_err(err500)?,
        "members": members,
        "meta": { "resourceType": "Group", "created": row.try_get::<String, _>("created_at").map_err(err500)? }
    }))
}

fn list_response(resources: Vec<Value>, start_index: i64, count: i64) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": resources.len(),
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": resources
    })
}

fn equality_filter(filter: Option<&str>, field: &str) -> ApiResult<Option<String>> {
    let Some(filter) = filter else {
        return Ok(None);
    };
    let prefix = format!("{field} eq ");
    if !filter.starts_with(&prefix) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("only the SCIM filter '{field} eq \"value\"' is supported"),
        ));
    }
    let quoted = filter[prefix.len()..].trim();
    if quoted.len() < 2 || !quoted.starts_with('"') || !quoted.ends_with('"') {
        return Err((
            StatusCode::BAD_REQUEST,
            "SCIM equality filter values must be quoted".into(),
        ));
    }
    let value = &quoted[1..quoted.len() - 1];
    if value.is_empty() || value.len() > 512 || value.contains('"') {
        return Err((
            StatusCode::BAD_REQUEST,
            "SCIM equality filter value is invalid".into(),
        ));
    }
    Ok(Some(value.to_string()))
}

fn primary_email(req: &ScimUserIn) -> Option<String> {
    req.emails.as_ref().and_then(|emails| {
        emails
            .iter()
            .find(|email| email.primary.unwrap_or(false))
            .or_else(|| emails.first())
            .map(|email| email.value.clone())
    })
}

fn validate_scim_text(label: &str, value: &str, max_len: usize) -> ApiResult<()> {
    if value.trim().is_empty()
        || value.len() > max_len
        || value.chars().any(|character| character.is_control())
    {
        return Err(bad_request(format!(
            "{label} must be 1-{max_len} non-control characters"
        )));
    }
    Ok(())
}

fn validate_scim_user(req: &ScimUserIn) -> ApiResult<()> {
    validate_scim_text("SCIM userName", &req.user_name, 256)?;
    if let Some(display_name) = &req.display_name {
        validate_scim_text("SCIM displayName", display_name, 256)?;
    }
    if let Some(external_id) = &req.external_id {
        validate_scim_text("SCIM externalId", external_id, 512)?;
    }
    if req.emails.as_ref().is_some_and(|emails| emails.len() > 16) {
        return Err(bad_request("a SCIM user may have at most 16 email entries"));
    }
    for email in req.emails.iter().flatten() {
        validate_scim_text("SCIM email", &email.value, 320)?;
        if !email.value.contains('@') {
            return Err(bad_request("SCIM email must contain '@'"));
        }
    }
    Ok(())
}

fn validate_scim_group(req: &ScimGroupIn) -> ApiResult<()> {
    validate_scim_text("SCIM group displayName", &req.display_name, 256)?;
    if let Some(external_id) = &req.external_id {
        validate_scim_text("SCIM externalId", external_id, 512)?;
    }
    if req
        .members
        .as_ref()
        .is_some_and(|members| members.len() > 500)
    {
        return Err(bad_request(
            "a SCIM group may have at most 500 members per request",
        ));
    }
    for member in req.members.iter().flatten() {
        validate_scim_text("SCIM member id", &member.value, 128)?;
    }
    Ok(())
}

fn err500(e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(error = %e, "internal SCIM operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal server error".to_string(),
    )
}

fn bad_request(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
