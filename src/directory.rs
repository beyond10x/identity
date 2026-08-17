//! Organization membership and flat, tenant-scoped directory groups.
//!
//! Identity owns principals. A collaboration product needs to name one person and a set of people
//! without keeping its own copy of the directory, so this module adds two durable concepts:
//!
//! - an *organization membership*, which records that a principal belongs to this deployment's
//!   tenant, what kind of principal it is, and whether the membership is active;
//! - a *group*, which names a set of members inside that same tenant.
//!
//! Three properties are deliberate and load-bearing.
//!
//! **Groups are flat.** A group holds principals and never another group, so resolving membership
//! is one bounded indexed query with no recursion, no cycle detection, and no transitive closure
//! on an authority path. Hierarchy — teams inside teams, reporting lines, progression — belongs to
//! the collaboration product, which owns the workforce view.
//!
//! **Membership is direct only.** Being a member of one group never implies membership of another.
//!
//! **A directory group carries no authority.** Deployment-configured static groups remain the only
//! group vocabulary that reaches an authority response; adding a principal to a directory group
//! grants nothing, mints nothing, and changes no token. That separation is what allows an ordinary
//! product to manage its own membership without becoming a privilege-escalation path.
//!
//! An agent identity may hold an organization membership and may be a group member. Mixed human
//! and agent participation is the normal case for collaboration, and a group that could not hold
//! an agent would force a second grouping model downstream — the shadow directory this module
//! exists to prevent. An agent membership is still not a login: it never resolves a session, and
//! a non-human principal may not carry an email address, which is the join key of the static
//! authority table.

use anyhow::Result;
use axum::Json;
use axum::extract::{Path, State};
use axum::response::Response;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{
    AdmittedSession, AppState, HttpError, RowCap, StaticGroupMemberships, Store,
    admitted_session_for_audience, confidential_json, normalize_email, unix_time,
};

/// The exact audience an in-cluster directory consumer must present.
pub(crate) const DIRECTORY_AUDIENCE: &str = "urn:daemonloom:directory";

/// The deployment-configured static group that admits directory administration. Directory writes
/// reuse the existing static-group mechanism rather than introducing a second credential kind.
const DIRECTORY_ADMIN_GROUP: &str = "identity-directory-admin";

const PRINCIPAL_KINDS: [&str; 3] = ["agent", "human", "service"];
const MEMBERSHIP_STATUSES: [&str; 2] = ["active", "suspended"];
const ACTIVE_STATUS: &str = "active";

const MAX_DIRECTORY_PRINCIPALS: i64 = 100_000;
const MAX_DIRECTORY_GROUPS: i64 = 10_000;
const MAX_GROUP_MEMBERS: i64 = 512;
const MAX_SUBJECT_GROUPS: i64 = 512;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_DISPLAY_NAME_CHARACTERS: usize = 128;
const MAX_GROUP_KEY_BYTES: usize = 64;

/// A durable organization membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberRecord {
    pub(crate) subject: String,
    pub(crate) principal_kind: String,
    pub(crate) email: Option<String>,
    pub(crate) display_name: String,
    pub(crate) status: String,
}

impl MemberRecord {
    fn is_active(&self) -> bool {
        self.status == ACTIVE_STATUS
    }
}

/// A durable group record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupRecord {
    pub(crate) group_key: String,
    pub(crate) display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberRequest {
    principal_kind: String,
    display_name: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupRequest {
    display_name: String,
}

#[derive(Debug, Serialize)]
struct MemberView {
    iss: String,
    dl_tenant: String,
    sub: String,
    principal_kind: String,
    display_name: String,
    email: Option<String>,
    status: String,
}

#[derive(Debug, Serialize)]
struct GroupSummaryView {
    group_key: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct MembershipView {
    iss: String,
    dl_tenant: String,
    sub: String,
    principal_kind: String,
    display_name: String,
    email: Option<String>,
    status: String,
    groups: Vec<GroupSummaryView>,
    /// Always false. A directory group is a naming concept; it never widens authority.
    groups_carry_authority: bool,
}

#[derive(Debug, Serialize)]
struct GroupView {
    iss: String,
    dl_tenant: String,
    group_key: String,
    display_name: String,
    /// Flat by construction: a group may not contain another group.
    nested: bool,
    /// Direct by construction: membership is never inherited.
    membership: &'static str,
    /// Always false, for the same reason as `MembershipView::groups_carry_authority`.
    carries_authority: bool,
    member_count: usize,
    members: Vec<GroupMemberView>,
}

#[derive(Debug, Serialize)]
struct GroupMemberView {
    sub: String,
    principal_kind: String,
    display_name: String,
}

/// Additive schema for the local single-process store.
pub(crate) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS directory_principals (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       principal_kind TEXT NOT NULL,
       email TEXT,
       display_name TEXT NOT NULL,
       status TEXT NOT NULL,
       created_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL,
       PRIMARY KEY (tenant_id, subject)
     );
     CREATE TABLE IF NOT EXISTS directory_groups (
       tenant_id TEXT NOT NULL,
       group_key TEXT NOT NULL,
       display_name TEXT NOT NULL,
       created_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL,
       PRIMARY KEY (tenant_id, group_key)
     );
     CREATE TABLE IF NOT EXISTS directory_group_members (
       tenant_id TEXT NOT NULL,
       group_key TEXT NOT NULL,
       subject TEXT NOT NULL,
       added_at INTEGER NOT NULL,
       PRIMARY KEY (tenant_id, group_key, subject),
       FOREIGN KEY (tenant_id, group_key)
         REFERENCES directory_groups (tenant_id, group_key),
       FOREIGN KEY (tenant_id, subject)
         REFERENCES directory_principals (tenant_id, subject)
     );
     CREATE INDEX IF NOT EXISTS directory_group_members_by_subject
       ON directory_group_members (tenant_id, subject);";

/// Additive schema for the clustered store. Every statement is `IF NOT EXISTS` and no existing
/// table, column, index, or row is read, rewritten, or dropped.
pub(crate) const POSTGRES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS directory_principals (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       principal_kind TEXT NOT NULL,
       email TEXT,
       display_name TEXT NOT NULL,
       status TEXT NOT NULL,
       created_at BIGINT NOT NULL,
       updated_at BIGINT NOT NULL,
       PRIMARY KEY (tenant_id, subject)
     );
     CREATE TABLE IF NOT EXISTS directory_groups (
       tenant_id TEXT NOT NULL,
       group_key TEXT NOT NULL,
       display_name TEXT NOT NULL,
       created_at BIGINT NOT NULL,
       updated_at BIGINT NOT NULL,
       PRIMARY KEY (tenant_id, group_key)
     );
     CREATE TABLE IF NOT EXISTS directory_group_members (
       tenant_id TEXT NOT NULL,
       group_key TEXT NOT NULL,
       subject TEXT NOT NULL,
       added_at BIGINT NOT NULL,
       PRIMARY KEY (tenant_id, group_key, subject),
       FOREIGN KEY (tenant_id, group_key)
         REFERENCES directory_groups (tenant_id, group_key),
       FOREIGN KEY (tenant_id, subject)
         REFERENCES directory_principals (tenant_id, subject)
     );
     CREATE INDEX IF NOT EXISTS directory_group_members_by_subject
       ON directory_group_members (tenant_id, subject);";

fn validated_subject(value: &str) -> Result<String, HttpError> {
    let subject = value.trim();
    if !(1..=MAX_SUBJECT_BYTES).contains(&subject.len())
        || !subject.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(HttpError::invalid(
            "a directory subject must be 1-255 printable ASCII characters without whitespace",
        ));
    }
    Ok(subject.to_owned())
}

fn validated_group_key(value: &str) -> Result<String, HttpError> {
    let key = value.trim().to_ascii_lowercase();
    let admitted = (1..=MAX_GROUP_KEY_BYTES).contains(&key.len())
        && key.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'-' | b'_')))
        });
    if !admitted {
        return Err(HttpError::invalid(
            "a group key must be a lowercase name of at most 64 characters starting with a letter",
        ));
    }
    Ok(key)
}

fn validated_display_name(value: &str) -> Result<String, HttpError> {
    let name = value.trim();
    if !(1..=MAX_DISPLAY_NAME_CHARACTERS).contains(&name.chars().count())
        || name.chars().any(char::is_control)
    {
        return Err(HttpError::invalid(
            "a display name must be 1-128 characters without control characters",
        ));
    }
    Ok(name.to_owned())
}

fn validated_principal_kind(value: &str) -> Result<String, HttpError> {
    let kind = value.trim().to_ascii_lowercase();
    if !PRINCIPAL_KINDS.contains(&kind.as_str()) {
        return Err(HttpError::invalid(
            "a principal kind must be one of agent, human, or service",
        ));
    }
    Ok(kind)
}

fn validated_status(value: Option<&str>) -> Result<String, HttpError> {
    let status = value.unwrap_or(ACTIVE_STATUS).trim().to_ascii_lowercase();
    if !MEMBERSHIP_STATUSES.contains(&status.as_str()) {
        return Err(HttpError::invalid(
            "a membership status must be active or suspended",
        ));
    }
    Ok(status)
}

/// Only a human principal may carry a mailbox address. The static authority table joins on the
/// verified upstream email, so admitting an email on a machine principal would create a second,
/// unverified path into that join.
fn validated_email(kind: &str, value: Option<&str>) -> Result<Option<String>, HttpError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if kind != "human" {
        return Err(HttpError::invalid(
            "only a human principal may carry an email address",
        ));
    }
    normalize_email(value)
        .map(Some)
        .map_err(|_| HttpError::invalid("a directory email must be a bounded ASCII mailbox"))
}

fn validated_member(subject: &str, request: &MemberRequest) -> Result<MemberRecord, HttpError> {
    let principal_kind = validated_principal_kind(&request.principal_kind)?;
    let email = validated_email(&principal_kind, request.email.as_deref())?;
    Ok(MemberRecord {
        subject: validated_subject(subject)?,
        principal_kind,
        email,
        display_name: validated_display_name(&request.display_name)?,
        status: validated_status(request.status.as_deref())?,
    })
}

/// Directory administration is an existing deployment-configured static group, evaluated against
/// the verified upstream email on every request. It introduces no new credential kind and no
/// durable role table, so a directory group can never grant directory administration.
fn require_directory_admin(
    memberships: &StaticGroupMemberships,
    admitted: &AdmittedSession,
) -> Result<(), HttpError> {
    if memberships
        .groups_for(&admitted.tenant_id, admitted.email.as_deref())
        .iter()
        .any(|group| group == DIRECTORY_ADMIN_GROUP)
    {
        return Ok(());
    }
    Err(HttpError::forbidden(
        "directory administration requires the identity-directory-admin static group",
    ))
}

async fn read_member(
    store: &Store,
    tenant_id: &str,
    subject: &str,
) -> Result<Option<MemberRecord>> {
    match store {
        Store::Sqlite(_) => store
            .sqlite_connection()?
            .query_row(
                "SELECT subject, principal_kind, email, display_name, status
                 FROM directory_principals WHERE tenant_id = ?1 AND subject = ?2",
                params![tenant_id, subject],
                |row| {
                    Ok(MemberRecord {
                        subject: row.get(0)?,
                        principal_kind: row.get(1)?,
                        email: row.get(2)?,
                        display_name: row.get(3)?,
                        status: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into),
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query_opt(
                "SELECT subject, principal_kind, email, display_name, status
                 FROM directory_principals WHERE tenant_id = $1 AND subject = $2",
                &[&tenant_id, &subject],
            )
            .await
            .map(|row| {
                row.map(|row| MemberRecord {
                    subject: row.get(0),
                    principal_kind: row.get(1),
                    email: row.get(2),
                    display_name: row.get(3),
                    status: row.get(4),
                })
            })
            .map_err(Into::into),
    }
}

pub(crate) async fn write_member(
    store: &Store,
    tenant_id: &str,
    record: &MemberRecord,
) -> Result<()> {
    let now = unix_time()?;
    match store {
        Store::Sqlite(_) => {
            store.sqlite_connection()?.execute(
                "INSERT INTO directory_principals (
                   tenant_id, subject, principal_kind, email, display_name, status,
                   created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT (tenant_id, subject) DO UPDATE SET
                   principal_kind = excluded.principal_kind,
                   email = excluded.email,
                   display_name = excluded.display_name,
                   status = excluded.status,
                   updated_at = excluded.updated_at",
                params![
                    tenant_id,
                    record.subject,
                    record.principal_kind,
                    record.email,
                    record.display_name,
                    record.status,
                    now,
                ],
            )?;
        }
        Store::Postgres(postgres) => {
            postgres
                .client()
                .await?
                .execute(
                    "INSERT INTO directory_principals (
                       tenant_id, subject, principal_kind, email, display_name, status,
                       created_at, updated_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
                     ON CONFLICT (tenant_id, subject) DO UPDATE SET
                       principal_kind = excluded.principal_kind,
                       email = excluded.email,
                       display_name = excluded.display_name,
                       status = excluded.status,
                       updated_at = excluded.updated_at",
                    &[
                        &tenant_id,
                        &record.subject,
                        &record.principal_kind,
                        &record.email,
                        &record.display_name,
                        &record.status,
                        &now,
                    ],
                )
                .await?;
        }
    }
    Ok(())
}

async fn read_group(
    store: &Store,
    tenant_id: &str,
    group_key: &str,
) -> Result<Option<GroupRecord>> {
    match store {
        Store::Sqlite(_) => store
            .sqlite_connection()?
            .query_row(
                "SELECT group_key, display_name FROM directory_groups
                 WHERE tenant_id = ?1 AND group_key = ?2",
                params![tenant_id, group_key],
                |row| {
                    Ok(GroupRecord {
                        group_key: row.get(0)?,
                        display_name: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into),
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query_opt(
                "SELECT group_key, display_name FROM directory_groups
                 WHERE tenant_id = $1 AND group_key = $2",
                &[&tenant_id, &group_key],
            )
            .await
            .map(|row| {
                row.map(|row| GroupRecord {
                    group_key: row.get(0),
                    display_name: row.get(1),
                })
            })
            .map_err(Into::into),
    }
}

pub(crate) async fn write_group(
    store: &Store,
    tenant_id: &str,
    record: &GroupRecord,
) -> Result<()> {
    let now = unix_time()?;
    match store {
        Store::Sqlite(_) => {
            store.sqlite_connection()?.execute(
                "INSERT INTO directory_groups (
                   tenant_id, group_key, display_name, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT (tenant_id, group_key) DO UPDATE SET
                   display_name = excluded.display_name,
                   updated_at = excluded.updated_at",
                params![tenant_id, record.group_key, record.display_name, now],
            )?;
        }
        Store::Postgres(postgres) => {
            postgres
                .client()
                .await?
                .execute(
                    "INSERT INTO directory_groups (
                       tenant_id, group_key, display_name, created_at, updated_at
                     ) VALUES ($1, $2, $3, $4, $4)
                     ON CONFLICT (tenant_id, group_key) DO UPDATE SET
                       display_name = excluded.display_name,
                       updated_at = excluded.updated_at",
                    &[&tenant_id, &record.group_key, &record.display_name, &now],
                )
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn write_group_member(
    store: &Store,
    tenant_id: &str,
    group_key: &str,
    subject: &str,
) -> Result<()> {
    let now = unix_time()?;
    match store {
        Store::Sqlite(_) => {
            store.sqlite_connection()?.execute(
                "INSERT INTO directory_group_members (tenant_id, group_key, subject, added_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (tenant_id, group_key, subject) DO NOTHING",
                params![tenant_id, group_key, subject, now],
            )?;
        }
        Store::Postgres(postgres) => {
            postgres
                .client()
                .await?
                .execute(
                    "INSERT INTO directory_group_members (tenant_id, group_key, subject, added_at)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (tenant_id, group_key, subject) DO NOTHING",
                    &[&tenant_id, &group_key, &subject, &now],
                )
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn erase_group_member(
    store: &Store,
    tenant_id: &str,
    group_key: &str,
    subject: &str,
) -> Result<bool> {
    let removed = match store {
        Store::Sqlite(_) => store.sqlite_connection()?.execute(
            "DELETE FROM directory_group_members
             WHERE tenant_id = ?1 AND group_key = ?2 AND subject = ?3",
            params![tenant_id, group_key, subject],
        )?,
        Store::Postgres(postgres) => {
            let removed = postgres
                .client()
                .await?
                .execute(
                    "DELETE FROM directory_group_members
                     WHERE tenant_id = $1 AND group_key = $2 AND subject = $3",
                    &[&tenant_id, &group_key, &subject],
                )
                .await?;
            usize::try_from(removed).unwrap_or(usize::MAX)
        }
    };
    Ok(removed > 0)
}

/// The direct groups of one principal. A suspended membership resolves to no groups at all, so a
/// suspension is one authoritative operation rather than a sweep over every group.
pub(crate) async fn resolve_subject_groups(
    store: &Store,
    tenant_id: &str,
    subject: &str,
) -> Result<Vec<GroupRecord>> {
    match store {
        Store::Sqlite(_) => {
            let connection = store.sqlite_connection()?;
            let mut statement = connection.prepare(
                "SELECT group_rows.group_key, group_rows.display_name
                 FROM directory_group_members AS member_rows
                 JOIN directory_groups AS group_rows
                   ON group_rows.tenant_id = member_rows.tenant_id
                  AND group_rows.group_key = member_rows.group_key
                 JOIN directory_principals AS principal_rows
                   ON principal_rows.tenant_id = member_rows.tenant_id
                  AND principal_rows.subject = member_rows.subject
                 WHERE member_rows.tenant_id = ?1 AND member_rows.subject = ?2
                   AND principal_rows.status = ?3
                 ORDER BY group_rows.group_key
                 LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![tenant_id, subject, ACTIVE_STATUS, MAX_SUBJECT_GROUPS],
                |row| {
                    Ok(GroupRecord {
                        group_key: row.get(0)?,
                        display_name: row.get(1)?,
                    })
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        }
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query(
                "SELECT group_rows.group_key, group_rows.display_name
                 FROM directory_group_members AS member_rows
                 JOIN directory_groups AS group_rows
                   ON group_rows.tenant_id = member_rows.tenant_id
                  AND group_rows.group_key = member_rows.group_key
                 JOIN directory_principals AS principal_rows
                   ON principal_rows.tenant_id = member_rows.tenant_id
                  AND principal_rows.subject = member_rows.subject
                 WHERE member_rows.tenant_id = $1 AND member_rows.subject = $2
                   AND principal_rows.status = $3
                 ORDER BY group_rows.group_key
                 LIMIT $4",
                &[&tenant_id, &subject, &ACTIVE_STATUS, &MAX_SUBJECT_GROUPS],
            )
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| GroupRecord {
                        group_key: row.get(0),
                        display_name: row.get(1),
                    })
                    .collect()
            })
            .map_err(Into::into),
    }
}

/// The active members of one group, ordered by subject. Suspended memberships are absent.
pub(crate) async fn resolve_group_members(
    store: &Store,
    tenant_id: &str,
    group_key: &str,
) -> Result<Vec<MemberRecord>> {
    match store {
        Store::Sqlite(_) => {
            let connection = store.sqlite_connection()?;
            let mut statement = connection.prepare(
                "SELECT principal_rows.subject, principal_rows.principal_kind, principal_rows.email,
                        principal_rows.display_name, principal_rows.status
                 FROM directory_group_members AS member_rows
                 JOIN directory_principals AS principal_rows
                   ON principal_rows.tenant_id = member_rows.tenant_id
                  AND principal_rows.subject = member_rows.subject
                 WHERE member_rows.tenant_id = ?1 AND member_rows.group_key = ?2
                   AND principal_rows.status = ?3
                 ORDER BY principal_rows.subject
                 LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![tenant_id, group_key, ACTIVE_STATUS, MAX_GROUP_MEMBERS],
                |row| {
                    Ok(MemberRecord {
                        subject: row.get(0)?,
                        principal_kind: row.get(1)?,
                        email: row.get(2)?,
                        display_name: row.get(3)?,
                        status: row.get(4)?,
                    })
                },
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
        }
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query(
                "SELECT principal_rows.subject, principal_rows.principal_kind, principal_rows.email,
                        principal_rows.display_name, principal_rows.status
                 FROM directory_group_members AS member_rows
                 JOIN directory_principals AS principal_rows
                   ON principal_rows.tenant_id = member_rows.tenant_id
                  AND principal_rows.subject = member_rows.subject
                 WHERE member_rows.tenant_id = $1 AND member_rows.group_key = $2
                   AND principal_rows.status = $3
                 ORDER BY principal_rows.subject
                 LIMIT $4",
                &[&tenant_id, &group_key, &ACTIVE_STATUS, &MAX_GROUP_MEMBERS],
            )
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| MemberRecord {
                        subject: row.get(0),
                        principal_kind: row.get(1),
                        email: row.get(2),
                        display_name: row.get(3),
                        status: row.get(4),
                    })
                    .collect()
            })
            .map_err(Into::into),
    }
}

pub(crate) async fn upsert_member(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(subject): Path<String>,
    Json(request): Json<MemberRequest>,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    require_directory_admin(&state.config.static_group_memberships, &admitted)?;
    let record = validated_member(&subject, &request)?;
    let tenant_id = admitted.tenant_id;
    let known = read_member(&state.store, &tenant_id, &record.subject)
        .await
        .map_err(HttpError::internal)?
        .is_some();
    let _admission = if known {
        None
    } else {
        state
            .store
            .enforce_row_caps(&[RowCap {
                sqlite_count: "SELECT count(*) FROM directory_principals WHERE tenant_id = ?1",
                postgres_count:
                    "SELECT count(*)::BIGINT FROM directory_principals WHERE tenant_id = $1",
                arguments: &[tenant_id.as_str()],
                maximum: MAX_DIRECTORY_PRINCIPALS,
                label: "directory principals",
            }])
            .await?
    };
    write_member(&state.store, &tenant_id, &record)
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(MemberView {
        iss: state.config.issuer().to_owned(),
        dl_tenant: tenant_id,
        sub: record.subject,
        principal_kind: record.principal_kind,
        display_name: record.display_name,
        email: record.email,
        status: record.status,
    }))
}

pub(crate) async fn upsert_group(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(group_key): Path<String>,
    Json(request): Json<GroupRequest>,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    require_directory_admin(&state.config.static_group_memberships, &admitted)?;
    let record = GroupRecord {
        group_key: validated_group_key(&group_key)?,
        display_name: validated_display_name(&request.display_name)?,
    };
    let tenant_id = admitted.tenant_id;
    let known = read_group(&state.store, &tenant_id, &record.group_key)
        .await
        .map_err(HttpError::internal)?
        .is_some();
    let _admission = if known {
        None
    } else {
        state
            .store
            .enforce_row_caps(&[RowCap {
                sqlite_count: "SELECT count(*) FROM directory_groups WHERE tenant_id = ?1",
                postgres_count:
                    "SELECT count(*)::BIGINT FROM directory_groups WHERE tenant_id = $1",
                arguments: &[tenant_id.as_str()],
                maximum: MAX_DIRECTORY_GROUPS,
                label: "directory groups",
            }])
            .await?
    };
    write_group(&state.store, &tenant_id, &record)
        .await
        .map_err(HttpError::internal)?;
    group_response(&state, &tenant_id, &record).await
}

pub(crate) async fn add_group_member(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((group_key, subject)): Path<(String, String)>,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    require_directory_admin(&state.config.static_group_memberships, &admitted)?;
    let group_key = validated_group_key(&group_key)?;
    let subject = validated_subject(&subject)?;
    let tenant_id = admitted.tenant_id;
    let group = read_group(&state.store, &tenant_id, &group_key)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::missing("no such group in this tenant"))?;
    let member = read_member(&state.store, &tenant_id, &subject)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| {
            HttpError::unprocessable(
                "a group member must already hold an organization membership in this tenant",
            )
        })?;
    if !member.is_active() {
        return Err(HttpError::unprocessable(
            "a suspended organization membership cannot join a group",
        ));
    }
    let _admission = state
        .store
        .enforce_row_caps(&[
            RowCap {
                sqlite_count: "SELECT count(*) FROM directory_group_members
                     WHERE tenant_id = ?1 AND group_key = ?2",
                postgres_count: "SELECT count(*)::BIGINT FROM directory_group_members
                     WHERE tenant_id = $1 AND group_key = $2",
                arguments: &[tenant_id.as_str(), group_key.as_str()],
                maximum: MAX_GROUP_MEMBERS,
                label: "group members",
            },
            RowCap {
                sqlite_count: "SELECT count(*) FROM directory_group_members
                     WHERE tenant_id = ?1 AND subject = ?2",
                postgres_count: "SELECT count(*)::BIGINT FROM directory_group_members
                     WHERE tenant_id = $1 AND subject = $2",
                arguments: &[tenant_id.as_str(), subject.as_str()],
                maximum: MAX_SUBJECT_GROUPS,
                label: "group memberships for one subject",
            },
        ])
        .await?;
    write_group_member(&state.store, &tenant_id, &group_key, &subject)
        .await
        .map_err(HttpError::internal)?;
    group_response(&state, &tenant_id, &group).await
}

pub(crate) async fn remove_group_member(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((group_key, subject)): Path<(String, String)>,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    require_directory_admin(&state.config.static_group_memberships, &admitted)?;
    let group_key = validated_group_key(&group_key)?;
    let subject = validated_subject(&subject)?;
    let tenant_id = admitted.tenant_id;
    let group = read_group(&state.store, &tenant_id, &group_key)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::missing("no such group in this tenant"))?;
    if !erase_group_member(&state.store, &tenant_id, &group_key, &subject)
        .await
        .map_err(HttpError::internal)?
    {
        return Err(HttpError::missing("no such member in this group"));
    }
    group_response(&state, &tenant_id, &group).await
}

pub(crate) async fn read_group_view(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(group_key): Path<String>,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    let group_key = validated_group_key(&group_key)?;
    let tenant_id = admitted.tenant_id.clone();
    let group = read_group(&state.store, &tenant_id, &group_key)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::missing("no such group in this tenant"))?;
    if require_directory_admin(&state.config.static_group_memberships, &admitted).is_err() {
        let own_groups = resolve_subject_groups(&state.store, &tenant_id, &admitted.subject)
            .await
            .map_err(HttpError::internal)?;
        if !own_groups.iter().any(|own| own.group_key == group_key) {
            return Err(HttpError::forbidden(
                "reading a group requires membership of that group or directory administration",
            ));
        }
    }
    group_response(&state, &tenant_id, &group).await
}

pub(crate) async fn read_own_membership(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, HttpError> {
    let admitted = admitted_session_for_audience(&state, &headers, DIRECTORY_AUDIENCE).await?;
    let tenant_id = admitted.tenant_id;
    let member = read_member(&state.store, &tenant_id, &admitted.subject)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| {
            HttpError::missing("this principal holds no organization membership in this tenant")
        })?;
    let groups = if member.is_active() {
        resolve_subject_groups(&state.store, &tenant_id, &member.subject)
            .await
            .map_err(HttpError::internal)?
    } else {
        Vec::new()
    };
    Ok(confidential_json(MembershipView {
        iss: state.config.issuer().to_owned(),
        dl_tenant: tenant_id,
        sub: member.subject,
        principal_kind: member.principal_kind,
        display_name: member.display_name,
        email: member.email,
        status: member.status,
        groups: groups
            .into_iter()
            .map(|group| GroupSummaryView {
                group_key: group.group_key,
                display_name: group.display_name,
            })
            .collect(),
        groups_carry_authority: false,
    }))
}

async fn group_response(
    state: &AppState,
    tenant_id: &str,
    group: &GroupRecord,
) -> Result<Response, HttpError> {
    let members = resolve_group_members(&state.store, tenant_id, &group.group_key)
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(GroupView {
        iss: state.config.issuer().to_owned(),
        dl_tenant: tenant_id.to_owned(),
        group_key: group.group_key.clone(),
        display_name: group.display_name.clone(),
        nested: false,
        membership: "direct",
        carries_authority: false,
        member_count: members.len(),
        members: members
            .into_iter()
            .map(|member| GroupMemberView {
                sub: member.subject,
                principal_kind: member.principal_kind,
                display_name: member.display_name,
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        DIRECTORY_ADMIN_GROUP, GroupRecord, MemberRecord, MemberRequest, erase_group_member,
        require_directory_admin, resolve_group_members, resolve_subject_groups, validated_email,
        validated_group_key, validated_member, validated_subject, write_group, write_group_member,
        write_member,
    };
    use crate::{AdmittedSession, StaticGroupMemberships, Store};

    fn member(subject: &str, kind: &str, email: Option<&str>) -> MemberRecord {
        MemberRecord {
            subject: subject.to_owned(),
            principal_kind: kind.to_owned(),
            email: email.map(str::to_owned),
            display_name: format!("display {subject}"),
            status: "active".to_owned(),
        }
    }

    fn group(key: &str) -> GroupRecord {
        GroupRecord {
            group_key: key.to_owned(),
            display_name: format!("group {key}"),
        }
    }

    async fn seeded() -> Store {
        let store = Store::in_memory().unwrap();
        for record in [
            member("human-1", "human", Some("person@example.test")),
            member("agent-planner-1", "agent", None),
        ] {
            write_member(&store, "tenant-dev", &record).await.unwrap();
        }
        for key in ["project-atlas", "project-borealis"] {
            write_group(&store, "tenant-dev", &group(key))
                .await
                .unwrap();
        }
        store
    }

    #[tokio::test]
    async fn group_membership_is_flat_and_direct_only() {
        let store = seeded().await;
        write_group_member(&store, "tenant-dev", "project-atlas", "human-1")
            .await
            .unwrap();

        let resolved = resolve_subject_groups(&store, "tenant-dev", "human-1")
            .await
            .unwrap();
        assert_eq!(
            resolved
                .iter()
                .map(|group| group.group_key.as_str())
                .collect::<Vec<_>>(),
            vec!["project-atlas"],
            "membership of one group must not imply membership of another"
        );

        // A group key is not a principal, so a group can never be placed inside a group.
        assert!(
            write_group_member(&store, "tenant-dev", "project-atlas", "project-borealis")
                .await
                .is_err(),
            "a group must not be admissible as a member of another group"
        );
        assert!(
            write_group_member(&store, "tenant-dev", "project-atlas", "not-enrolled")
                .await
                .is_err(),
            "a member without an organization membership must be refused"
        );
    }

    #[tokio::test]
    async fn suspension_removes_a_principal_from_group_resolution() {
        let store = seeded().await;
        write_group_member(&store, "tenant-dev", "project-atlas", "human-1")
            .await
            .unwrap();
        let mut suspended = member("human-1", "human", Some("person@example.test"));
        suspended.status = "suspended".to_owned();
        write_member(&store, "tenant-dev", &suspended)
            .await
            .unwrap();

        assert!(
            resolve_subject_groups(&store, "tenant-dev", "human-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            resolve_group_members(&store, "tenant-dev", "project-atlas")
                .await
                .unwrap()
                .is_empty()
        );

        write_member(&store, "tenant-dev", &member("human-1", "human", None))
            .await
            .unwrap();
        assert_eq!(
            resolve_subject_groups(&store, "tenant-dev", "human-1")
                .await
                .unwrap()
                .len(),
            1,
            "reactivation must restore the preserved membership row"
        );
    }

    #[tokio::test]
    async fn an_agent_identity_is_an_ordinary_group_member_without_authority() {
        let store = seeded().await;
        for subject in ["human-1", "agent-planner-1"] {
            write_group_member(&store, "tenant-dev", "project-atlas", subject)
                .await
                .unwrap();
        }

        let members = resolve_group_members(&store, "tenant-dev", "project-atlas")
            .await
            .unwrap();
        assert_eq!(
            members
                .iter()
                .map(|member| (member.subject.as_str(), member.principal_kind.as_str()))
                .collect::<Vec<_>>(),
            vec![("agent-planner-1", "agent"), ("human-1", "human"),]
        );

        // A directory group is not an authority group. The static table is the only source of
        // authority groups and it is unaffected by directory membership.
        let authority = StaticGroupMemberships::new(vec![(
            "tenant-dev".to_owned(),
            "person@example.test".to_owned(),
            vec!["operator".to_owned()],
        )])
        .unwrap();
        assert_eq!(
            authority.groups_for("tenant-dev", Some("person@example.test")),
            vec!["operator"],
            "directory membership must not add an authority group"
        );
        assert!(
            authority.groups_for("tenant-dev", None).is_empty(),
            "an agent principal resolves no authority group at all"
        );

        // An agent may not carry the mailbox address that the static authority table joins on.
        assert!(validated_email("agent", Some("planner@example.test")).is_err());
        assert!(validated_email("human", Some("planner@example.test")).is_ok());
    }

    #[tokio::test]
    async fn directory_rows_are_tenant_scoped() {
        let store = seeded().await;
        write_group_member(&store, "tenant-dev", "project-atlas", "human-1")
            .await
            .unwrap();
        assert!(
            resolve_subject_groups(&store, "tenant-other", "human-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            resolve_group_members(&store, "tenant-other", "project-atlas")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            write_group_member(&store, "tenant-other", "project-atlas", "human-1")
                .await
                .is_err(),
            "a group in another tenant must not accept this tenant's principal"
        );
    }

    #[tokio::test]
    async fn removing_a_member_is_reported_exactly_once() {
        let store = seeded().await;
        write_group_member(&store, "tenant-dev", "project-atlas", "human-1")
            .await
            .unwrap();
        assert!(
            erase_group_member(&store, "tenant-dev", "project-atlas", "human-1")
                .await
                .unwrap()
        );
        assert!(
            !erase_group_member(&store, "tenant-dev", "project-atlas", "human-1")
                .await
                .unwrap()
        );
    }

    #[test]
    fn directory_input_vocabulary_is_closed() {
        assert_eq!(
            validated_group_key(" Project-Atlas ").unwrap(),
            "project-atlas"
        );
        for invalid in ["", "-leading", "9leading", &"a".repeat(65), "with space"] {
            assert!(validated_group_key(invalid).is_err(), "admitted {invalid}");
        }
        assert!(validated_subject("google|1234").is_ok());
        for invalid in ["", "with space", &"a".repeat(256)] {
            assert!(validated_subject(invalid).is_err(), "admitted {invalid}");
        }

        let request = MemberRequest {
            principal_kind: "robot".to_owned(),
            display_name: "Somebody".to_owned(),
            email: None,
            status: None,
        };
        assert!(validated_member("subject-1", &request).is_err());
        let request = MemberRequest {
            principal_kind: "human".to_owned(),
            display_name: "Somebody".to_owned(),
            email: None,
            status: Some("deleted".to_owned()),
        };
        assert!(validated_member("subject-1", &request).is_err());
        let request = MemberRequest {
            principal_kind: "human".to_owned(),
            display_name: "Somebody".to_owned(),
            email: Some("Somebody@Example.Test".to_owned()),
            status: None,
        };
        let record = validated_member(" subject-1 ", &request).unwrap();
        assert_eq!(record.subject, "subject-1");
        assert_eq!(record.email.as_deref(), Some("somebody@example.test"));
        assert_eq!(record.status, "active");
    }

    #[test]
    fn directory_administration_comes_only_from_the_static_group() {
        let memberships = StaticGroupMemberships::new(vec![
            (
                "tenant-dev".to_owned(),
                "admin@example.test".to_owned(),
                vec![DIRECTORY_ADMIN_GROUP.to_owned()],
            ),
            (
                "tenant-dev".to_owned(),
                "operator@example.test".to_owned(),
                vec!["operator".to_owned()],
            ),
        ])
        .unwrap();

        let session = |email: Option<&str>| AdmittedSession {
            tenant_id: "tenant-dev".to_owned(),
            subject: "google-subject".to_owned(),
            email: email.map(str::to_owned),
            expires_at: 0,
        };
        assert!(
            require_directory_admin(&memberships, &session(Some("admin@example.test"))).is_ok()
        );
        for denied in [
            Some("operator@example.test"),
            Some("other@example.test"),
            None,
        ] {
            assert!(
                require_directory_admin(&memberships, &session(denied)).is_err(),
                "admitted {denied:?} as a directory administrator"
            );
        }

        // The tenant binds too: the same email in another tenant is not an administrator.
        let other_tenant = AdmittedSession {
            tenant_id: "tenant-other".to_owned(),
            subject: "google-subject".to_owned(),
            email: Some("admin@example.test".to_owned()),
            expires_at: 0,
        };
        assert!(require_directory_admin(&memberships, &other_tenant).is_err());
    }
}
