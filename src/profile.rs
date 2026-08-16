//! The durable personal collaboration profile and its model-visible projection.
//!
//! Identity owns the profile lifecycle. A worker never touches this store; it receives an
//! immutable snapshot value that is rebuilt from the durable rows on every request and identified
//! by a digest over its own content.
//!
//! The rules this module enforces are the ones a person has to be able to rely on.
//!
//! - **A statement carries an epistemic state.** `observed` and `inferred` are what the system
//!   noticed or guessed; `confirmed` is what the person said; `revoked` and `rejected` are what
//!   the person withdrew or denied. Every statement preserves the evidence it came from.
//! - **An inference never silently becomes a confirmation.** The learning write path admits only
//!   `observed` and `inferred`, and the only transition into `confirmed` is an explicit act by the
//!   person on their own profile. There is no other writer.
//! - **The person can inspect, correct, forget, and revoke.** Inspection works regardless of
//!   consent, because a person must be able to see and delete what is retained about them even
//!   after they have stopped consenting to learning.
//! - **Profile-learning consent is its own consent.** It is not a datasource grant, not an
//!   endpoint authority, and not a scope. Granting it mints nothing; revoking it empties the
//!   projection without touching any other authority the person holds.
//! - **Secret material and excluded datasource content never enter a projection.** Both are
//!   refused when a statement is written and screened again when a snapshot is built, so a row
//!   that reached the database by some other route still cannot reach a model.
//!
//! Every profile route is self-scoped: the subject of the session is the subject of the profile.
//! No endpoint in this service reads or writes another principal's profile.

use std::collections::BTreeSet;

use anyhow::Result;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::screening::secret_shape;
use crate::{
    AppState, HttpError, RowCap, Store, admitted_session_for_audiences, confidential_json,
    hex_digest, random_token, unix_time, valid_b64_token,
};

/// The audience of the person's own control surface: inspection, consent, confirmation,
/// correction, revocation, and forgetting.
pub(crate) const PROFILE_AUDIENCE: &str = "urn:daemonloom:profile";

/// The audience of a learning consumer such as an agent harness. It reaches the immutable
/// projection and the learning write, and nothing else: the durable store, the withheld
/// statements, and the lifecycle controls are not addressable under it.
pub(crate) const PROFILE_PROJECTION_AUDIENCE: &str = "urn:daemonloom:profile-projection";

/// Audiences admitted to the person's durable profile and its lifecycle controls.
const PERSON_CONTROL_AUDIENCES: [&str; 1] = [PROFILE_AUDIENCE];

/// Audiences admitted to the projection and the learning write. The person may look at exactly
/// what a worker is given; a worker may not look at anything else.
const PROJECTION_AUDIENCES: [&str; 2] = [PROFILE_AUDIENCE, PROFILE_PROJECTION_AUDIENCE];

/// The one consent scope this module recognizes. It is deliberately not a Connector scope and not
/// an audience: it grants no access to anything.
const LEARNING_CONSENT_SCOPE: &str = "profile.learning";

const STATEMENT_KINDS: [&str; 4] = ["friction", "goal_horizon", "preference", "working_pattern"];
const GOAL_HORIZONS: [&str; 3] = ["long_term", "session", "short_term"];
const SOURCE_KINDS: [&str; 4] = ["conversation", "datasource", "person", "workflow_run"];
/// The only states a learning writer may create.
const LEARNED_STATES: [&str; 2] = ["inferred", "observed"];
/// The states the person may move a statement into when withdrawing it.
const RESOLVED_STATES: [&str; 2] = ["rejected", "revoked"];
const CONFIRMED_STATE: &str = "confirmed";
const PERSON_SOURCE_REFERENCE: &str = "person:self";

const STATEMENT_ID_PREFIX: &str = "dl_profile_stmt_v1_";
const SNAPSHOT_ID_PREFIX: &str = "dl_profile_snapshot_v1_";
const STATEMENT_ID_TOKEN_CHARACTERS: usize = 22;

const MAX_STATEMENT_CHARACTERS: usize = 512;
const MAX_SOURCE_ID_BYTES: usize = 128;
const MAX_STATEMENTS_PER_SUBJECT: i64 = 512;
const MAX_PROFILE_STATEMENTS: i64 = 200_000;
const MAX_PROFILE_CONSENTS: i64 = 100_000;
const MAX_EXCLUDED_SOURCES: usize = 64;

/// Additive schema for the local single-process store.
pub(crate) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS profile_consents (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       consent_scope TEXT NOT NULL,
       granted_at INTEGER NOT NULL,
       revoked_at INTEGER,
       PRIMARY KEY (tenant_id, subject, consent_scope)
     );
     CREATE TABLE IF NOT EXISTS profile_excluded_sources (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       source_reference TEXT NOT NULL,
       excluded_at INTEGER NOT NULL,
       PRIMARY KEY (tenant_id, subject, source_reference)
     );
     CREATE TABLE IF NOT EXISTS profile_statements (
       statement_id TEXT PRIMARY KEY,
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       kind TEXT NOT NULL,
       horizon TEXT,
       content TEXT NOT NULL,
       epistemic_state TEXT NOT NULL,
       source_kind TEXT NOT NULL,
       source_reference TEXT NOT NULL,
       observed_at INTEGER NOT NULL,
       created_at INTEGER NOT NULL,
       updated_at INTEGER NOT NULL,
       confirmed_at INTEGER,
       resolved_at INTEGER,
       superseded_by TEXT
     );
     CREATE INDEX IF NOT EXISTS profile_statements_by_subject
       ON profile_statements (tenant_id, subject);";

/// Additive schema for the clustered store. Every statement is `IF NOT EXISTS` and no existing
/// table, column, index, or row is read, rewritten, or dropped.
pub(crate) const POSTGRES_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS profile_consents (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       consent_scope TEXT NOT NULL,
       granted_at BIGINT NOT NULL,
       revoked_at BIGINT,
       PRIMARY KEY (tenant_id, subject, consent_scope)
     );
     CREATE TABLE IF NOT EXISTS profile_excluded_sources (
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       source_reference TEXT NOT NULL,
       excluded_at BIGINT NOT NULL,
       PRIMARY KEY (tenant_id, subject, source_reference)
     );
     CREATE TABLE IF NOT EXISTS profile_statements (
       statement_id TEXT PRIMARY KEY,
       tenant_id TEXT NOT NULL,
       subject TEXT NOT NULL,
       kind TEXT NOT NULL,
       horizon TEXT,
       content TEXT NOT NULL,
       epistemic_state TEXT NOT NULL,
       source_kind TEXT NOT NULL,
       source_reference TEXT NOT NULL,
       observed_at BIGINT NOT NULL,
       created_at BIGINT NOT NULL,
       updated_at BIGINT NOT NULL,
       confirmed_at BIGINT,
       resolved_at BIGINT,
       superseded_by TEXT
     );
     CREATE INDEX IF NOT EXISTS profile_statements_by_subject
       ON profile_statements (tenant_id, subject);";

/// One durable profile statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatementRecord {
    pub(crate) statement_id: String,
    pub(crate) kind: String,
    pub(crate) horizon: Option<String>,
    pub(crate) content: String,
    pub(crate) epistemic_state: String,
    pub(crate) source_kind: String,
    pub(crate) source_reference: String,
    pub(crate) observed_at: i64,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) confirmed_at: Option<i64>,
    pub(crate) resolved_at: Option<i64>,
    pub(crate) superseded_by: Option<String>,
}

/// The person's profile-learning consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsentRecord {
    pub(crate) learning: bool,
    pub(crate) granted_at: i64,
    pub(crate) revoked_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceRequest {
    kind: String,
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentRequest {
    learning: bool,
    #[serde(default)]
    excluded_sources: Vec<SourceRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatementRequest {
    kind: String,
    #[serde(default)]
    horizon: Option<String>,
    content: String,
    epistemic_state: String,
    source: SourceRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevocationRequest {
    epistemic_state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorrectionRequest {
    content: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    horizon: Option<String>,
}

/// The durable view returned to the person. It is not the projection and is never handed to a
/// worker: it carries lifecycle state, withheld statements, and the reason each is withheld.
#[derive(Debug, Serialize)]
struct ProfileView {
    iss: String,
    dl_tenant: String,
    sub: String,
    learning_consent: bool,
    consent_scope: &'static str,
    consent_granted_at: Option<i64>,
    consent_revoked_at: Option<i64>,
    excluded_sources: Vec<String>,
    statements: Vec<RetainedStatementView>,
}

#[derive(Debug, Serialize)]
struct RetainedStatementView {
    statement_id: String,
    kind: String,
    horizon: Option<String>,
    content: String,
    epistemic_state: String,
    source_kind: String,
    source_reference: String,
    observed_at: i64,
    created_at: i64,
    updated_at: i64,
    confirmed_at: Option<i64>,
    resolved_at: Option<i64>,
    superseded_by: Option<String>,
    model_visible: bool,
    withheld_reason: Option<&'static str>,
}

/// The immutable projection handed to a consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileSnapshot {
    iss: String,
    dl_tenant: String,
    sub: String,
    snapshot_id: String,
    /// Always true. Everything in this value is explicitly admitted to a model.
    model_visible: bool,
    learning_consent: bool,
    statement_count: usize,
    statements: Vec<SnapshotStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotStatement {
    statement_id: String,
    kind: String,
    horizon: Option<String>,
    /// One of `observed`, `inferred`, or `confirmed`. A withdrawn statement is absent entirely.
    epistemic_state: String,
    /// True only for a statement the person confirmed. An inference can never set this.
    confirmed: bool,
    content: String,
    source_kind: String,
    source_reference: String,
    observed_at: i64,
}

fn validated_kind(value: &str) -> Result<String, HttpError> {
    let kind = value.trim().to_ascii_lowercase();
    if !STATEMENT_KINDS.contains(&kind.as_str()) {
        return Err(HttpError::invalid(
            "a statement kind must be friction, goal_horizon, preference, or working_pattern",
        ));
    }
    Ok(kind)
}

/// A goal statement must name its horizon; every other kind must not carry one.
fn validated_horizon(kind: &str, value: Option<&str>) -> Result<Option<String>, HttpError> {
    let horizon = value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    match (kind, horizon) {
        ("goal_horizon", Some(horizon)) if GOAL_HORIZONS.contains(&horizon.as_str()) => {
            Ok(Some(horizon))
        }
        ("goal_horizon", _) => Err(HttpError::invalid(
            "a goal_horizon statement must name a long_term, session, or short_term horizon",
        )),
        (_, None) => Ok(None),
        (_, Some(_)) => Err(HttpError::invalid(
            "only a goal_horizon statement may carry a horizon",
        )),
    }
}

fn validated_content(value: &str) -> Result<String, HttpError> {
    let content = value.trim();
    if !(1..=MAX_STATEMENT_CHARACTERS).contains(&content.chars().count())
        || content.chars().any(char::is_control)
    {
        return Err(HttpError::invalid(
            "statement content must be 1-512 characters without control characters",
        ));
    }
    if let Some(reason) = secret_shape(content) {
        return Err(HttpError::unprocessable(format!(
            "a profile statement may not retain {reason}"
        )));
    }
    Ok(content.to_owned())
}

/// Source evidence is a closed `kind:id` pair rather than free text, so a projection cannot carry
/// an unbounded blob under the name of provenance.
fn validated_source(source: &SourceRequest) -> Result<(String, String), HttpError> {
    let kind = source.kind.trim().to_ascii_lowercase();
    if !SOURCE_KINDS.contains(&kind.as_str()) {
        return Err(HttpError::invalid(
            "a source kind must be conversation, datasource, person, or workflow_run",
        ));
    }
    let id = source.id.trim();
    let admitted = (1..=MAX_SOURCE_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        });
    if !admitted {
        return Err(HttpError::invalid(
            "a source id must be 1-128 characters of [A-Za-z0-9._:@-] starting alphanumerically",
        ));
    }
    let reference = format!("{kind}:{id}");
    if let Some(reason) = secret_shape(&reference) {
        return Err(HttpError::unprocessable(format!(
            "a source reference may not carry {reason}"
        )));
    }
    Ok((kind, reference))
}

fn validated_learned_state(value: &str) -> Result<String, HttpError> {
    let state = value.trim().to_ascii_lowercase();
    if !LEARNED_STATES.contains(&state.as_str()) {
        return Err(HttpError::unprocessable(
            "a learned statement must be observed or inferred; only the person can confirm",
        ));
    }
    Ok(state)
}

fn validated_resolved_state(value: &str) -> Result<String, HttpError> {
    let state = value.trim().to_ascii_lowercase();
    if !RESOLVED_STATES.contains(&state.as_str()) {
        return Err(HttpError::invalid(
            "a withdrawal must set the state to revoked or rejected",
        ));
    }
    Ok(state)
}

fn validated_statement_id(value: &str) -> Result<String, HttpError> {
    let admitted = value
        .strip_prefix(STATEMENT_ID_PREFIX)
        .is_some_and(|token| {
            valid_b64_token(
                token,
                STATEMENT_ID_TOKEN_CHARACTERS,
                STATEMENT_ID_TOKEN_CHARACTERS,
            )
        });
    if admitted {
        Ok(value.to_owned())
    } else {
        Err(HttpError::invalid("malformed profile statement id"))
    }
}

fn validated_exclusions(sources: &[SourceRequest]) -> Result<BTreeSet<String>, HttpError> {
    if sources.len() > MAX_EXCLUDED_SOURCES {
        return Err(HttpError::invalid(
            "at most 64 excluded sources may be recorded",
        ));
    }
    sources
        .iter()
        .map(|source| validated_source(source).map(|(_, reference)| reference))
        .collect()
}

/// Why a retained statement is absent from the projection, or `None` when it is admitted.
fn withheld_reason(
    record: &StatementRecord,
    learning: bool,
    exclusions: &BTreeSet<String>,
) -> Option<&'static str> {
    if !learning {
        return Some("profile-learning consent is not granted");
    }
    if RESOLVED_STATES.contains(&record.epistemic_state.as_str()) {
        return Some("the person withdrew this statement");
    }
    if exclusions.contains(&record.source_reference) {
        return Some("the source is excluded from profile learning");
    }
    if secret_shape(&record.content).is_some() || secret_shape(&record.source_reference).is_some() {
        return Some("the retained value is credential-shaped");
    }
    None
}

/// Builds the immutable projection. This is the only function that produces a value a worker may
/// see, and it is pure: the same durable state always yields the same snapshot and the same id.
pub(crate) fn project(
    issuer: &str,
    tenant_id: &str,
    subject: &str,
    consent: Option<ConsentRecord>,
    exclusions: &BTreeSet<String>,
    statements: &[StatementRecord],
) -> ProfileSnapshot {
    let learning = consent.is_some_and(|consent| consent.learning);
    let statements = statements
        .iter()
        .filter(|record| withheld_reason(record, learning, exclusions).is_none())
        .map(|record| SnapshotStatement {
            statement_id: record.statement_id.clone(),
            kind: record.kind.clone(),
            horizon: record.horizon.clone(),
            confirmed: record.epistemic_state == CONFIRMED_STATE,
            epistemic_state: record.epistemic_state.clone(),
            content: record.content.clone(),
            source_kind: record.source_kind.clone(),
            source_reference: record.source_reference.clone(),
            observed_at: record.observed_at,
        })
        .collect::<Vec<_>>();
    let snapshot_id = snapshot_id(issuer, tenant_id, subject, learning, &statements);
    ProfileSnapshot {
        iss: issuer.to_owned(),
        dl_tenant: tenant_id.to_owned(),
        sub: subject.to_owned(),
        snapshot_id,
        model_visible: true,
        learning_consent: learning,
        statement_count: statements.len(),
        statements,
    }
}

fn snapshot_id(
    issuer: &str,
    tenant_id: &str,
    subject: &str,
    learning: bool,
    statements: &[SnapshotStatement],
) -> String {
    let mut digest = Sha256::new();
    for field in [issuer, tenant_id, subject, if learning { "1" } else { "0" }] {
        absorb(&mut digest, field);
    }
    for statement in statements {
        for field in [
            statement.statement_id.as_str(),
            statement.kind.as_str(),
            statement.horizon.as_deref().unwrap_or(""),
            statement.epistemic_state.as_str(),
            statement.content.as_str(),
            statement.source_kind.as_str(),
            statement.source_reference.as_str(),
        ] {
            absorb(&mut digest, field);
        }
        absorb(&mut digest, &statement.observed_at.to_string());
    }
    format!("{SNAPSHOT_ID_PREFIX}{}", hex_digest(&digest.finalize()[..]))
}

fn absorb(digest: &mut Sha256, field: &str) {
    digest.update((field.len() as u64).to_be_bytes());
    digest.update(field.as_bytes());
}

async fn read_consent(
    store: &Store,
    tenant_id: &str,
    subject: &str,
) -> Result<Option<ConsentRecord>> {
    match store {
        Store::Sqlite(_) => store
            .sqlite_connection()?
            .query_row(
                "SELECT granted_at, revoked_at FROM profile_consents
                 WHERE tenant_id = ?1 AND subject = ?2 AND consent_scope = ?3",
                params![tenant_id, subject, LEARNING_CONSENT_SCOPE],
                |row| {
                    let revoked_at: Option<i64> = row.get(1)?;
                    Ok(ConsentRecord {
                        learning: revoked_at.is_none(),
                        granted_at: row.get(0)?,
                        revoked_at,
                    })
                },
            )
            .optional()
            .map_err(Into::into),
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query_opt(
                "SELECT granted_at, revoked_at FROM profile_consents
                 WHERE tenant_id = $1 AND subject = $2 AND consent_scope = $3",
                &[&tenant_id, &subject, &LEARNING_CONSENT_SCOPE],
            )
            .await
            .map(|row| {
                row.map(|row| {
                    let revoked_at: Option<i64> = row.get(1);
                    ConsentRecord {
                        learning: revoked_at.is_none(),
                        granted_at: row.get(0),
                        revoked_at,
                    }
                })
            })
            .map_err(Into::into),
    }
}

pub(crate) async fn write_consent(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    learning: bool,
) -> Result<()> {
    let now = unix_time()?;
    let revoked_at = if learning { None } else { Some(now) };
    match store {
        Store::Sqlite(_) => {
            store.sqlite_connection()?.execute(
                "INSERT INTO profile_consents
                   (tenant_id, subject, consent_scope, granted_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (tenant_id, subject, consent_scope) DO UPDATE SET
                   granted_at = excluded.granted_at,
                   revoked_at = excluded.revoked_at",
                params![tenant_id, subject, LEARNING_CONSENT_SCOPE, now, revoked_at],
            )?;
        }
        Store::Postgres(postgres) => {
            postgres
                .client()
                .await?
                .execute(
                    "INSERT INTO profile_consents
                       (tenant_id, subject, consent_scope, granted_at, revoked_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (tenant_id, subject, consent_scope) DO UPDATE SET
                       granted_at = excluded.granted_at,
                       revoked_at = excluded.revoked_at",
                    &[
                        &tenant_id,
                        &subject,
                        &LEARNING_CONSENT_SCOPE,
                        &now,
                        &revoked_at,
                    ],
                )
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn read_exclusions(
    store: &Store,
    tenant_id: &str,
    subject: &str,
) -> Result<BTreeSet<String>> {
    match store {
        Store::Sqlite(_) => {
            let connection = store.sqlite_connection()?;
            let mut statement = connection.prepare(
                "SELECT source_reference FROM profile_excluded_sources
                 WHERE tenant_id = ?1 AND subject = ?2 ORDER BY source_reference",
            )?;
            let rows = statement.query_map(params![tenant_id, subject], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<BTreeSet<String>>>()
                .map_err(Into::into)
        }
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query(
                "SELECT source_reference FROM profile_excluded_sources
                 WHERE tenant_id = $1 AND subject = $2 ORDER BY source_reference",
                &[&tenant_id, &subject],
            )
            .await
            .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
            .map_err(Into::into),
    }
}

pub(crate) async fn replace_exclusions(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    exclusions: &BTreeSet<String>,
) -> Result<()> {
    let now = unix_time()?;
    match store {
        Store::Sqlite(_) => {
            let connection = store.sqlite_connection()?;
            connection.execute(
                "DELETE FROM profile_excluded_sources WHERE tenant_id = ?1 AND subject = ?2",
                params![tenant_id, subject],
            )?;
            for reference in exclusions {
                connection.execute(
                    "INSERT INTO profile_excluded_sources
                       (tenant_id, subject, source_reference, excluded_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![tenant_id, subject, reference, now],
                )?;
            }
        }
        Store::Postgres(postgres) => {
            let client = postgres.client().await?;
            client
                .execute(
                    "DELETE FROM profile_excluded_sources WHERE tenant_id = $1 AND subject = $2",
                    &[&tenant_id, &subject],
                )
                .await?;
            for reference in exclusions {
                client
                    .execute(
                        "INSERT INTO profile_excluded_sources
                           (tenant_id, subject, source_reference, excluded_at)
                         VALUES ($1, $2, $3, $4)",
                        &[&tenant_id, &subject, reference, &now],
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn write_statement(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    record: &StatementRecord,
) -> Result<()> {
    match store {
        Store::Sqlite(_) => {
            store.sqlite_connection()?.execute(
                "INSERT INTO profile_statements (
                   statement_id, tenant_id, subject, kind, horizon, content, epistemic_state,
                   source_kind, source_reference, observed_at, created_at, updated_at,
                   confirmed_at, resolved_at, superseded_by
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    record.statement_id,
                    tenant_id,
                    subject,
                    record.kind,
                    record.horizon,
                    record.content,
                    record.epistemic_state,
                    record.source_kind,
                    record.source_reference,
                    record.observed_at,
                    record.created_at,
                    record.updated_at,
                    record.confirmed_at,
                    record.resolved_at,
                    record.superseded_by,
                ],
            )?;
        }
        Store::Postgres(postgres) => {
            postgres
                .client()
                .await?
                .execute(
                    "INSERT INTO profile_statements (
                       statement_id, tenant_id, subject, kind, horizon, content, epistemic_state,
                       source_kind, source_reference, observed_at, created_at, updated_at,
                       confirmed_at, resolved_at, superseded_by
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                    &[
                        &record.statement_id,
                        &tenant_id,
                        &subject,
                        &record.kind,
                        &record.horizon,
                        &record.content,
                        &record.epistemic_state,
                        &record.source_kind,
                        &record.source_reference,
                        &record.observed_at,
                        &record.created_at,
                        &record.updated_at,
                        &record.confirmed_at,
                        &record.resolved_at,
                        &record.superseded_by,
                    ],
                )
                .await?;
        }
    }
    Ok(())
}

const STATEMENT_COLUMNS: &str = "statement_id, kind, horizon, content, epistemic_state,
     source_kind, source_reference, observed_at, created_at, updated_at, confirmed_at,
     resolved_at, superseded_by";

fn statement_from_sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StatementRecord> {
    Ok(StatementRecord {
        statement_id: row.get(0)?,
        kind: row.get(1)?,
        horizon: row.get(2)?,
        content: row.get(3)?,
        epistemic_state: row.get(4)?,
        source_kind: row.get(5)?,
        source_reference: row.get(6)?,
        observed_at: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        confirmed_at: row.get(10)?,
        resolved_at: row.get(11)?,
        superseded_by: row.get(12)?,
    })
}

fn statement_from_postgres_row(row: &tokio_postgres::Row) -> StatementRecord {
    StatementRecord {
        statement_id: row.get(0),
        kind: row.get(1),
        horizon: row.get(2),
        content: row.get(3),
        epistemic_state: row.get(4),
        source_kind: row.get(5),
        source_reference: row.get(6),
        observed_at: row.get(7),
        created_at: row.get(8),
        updated_at: row.get(9),
        confirmed_at: row.get(10),
        resolved_at: row.get(11),
        superseded_by: row.get(12),
    }
}

pub(crate) async fn read_statement(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    statement_id: &str,
) -> Result<Option<StatementRecord>> {
    match store {
        Store::Sqlite(_) => store
            .sqlite_connection()?
            .query_row(
                &format!(
                    "SELECT {STATEMENT_COLUMNS} FROM profile_statements
                     WHERE tenant_id = ?1 AND subject = ?2 AND statement_id = ?3"
                ),
                params![tenant_id, subject, statement_id],
                statement_from_sqlite_row,
            )
            .optional()
            .map_err(Into::into),
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query_opt(
                &format!(
                    "SELECT {STATEMENT_COLUMNS} FROM profile_statements
                     WHERE tenant_id = $1 AND subject = $2 AND statement_id = $3"
                ),
                &[&tenant_id, &subject, &statement_id],
            )
            .await
            .map(|row| row.as_ref().map(statement_from_postgres_row))
            .map_err(Into::into),
    }
}

pub(crate) async fn read_statements(
    store: &Store,
    tenant_id: &str,
    subject: &str,
) -> Result<Vec<StatementRecord>> {
    match store {
        Store::Sqlite(_) => {
            let connection = store.sqlite_connection()?;
            let mut statement = connection.prepare(&format!(
                "SELECT {STATEMENT_COLUMNS} FROM profile_statements
                 WHERE tenant_id = ?1 AND subject = ?2 ORDER BY statement_id LIMIT ?3"
            ))?;
            let rows = statement.query_map(
                params![tenant_id, subject, MAX_STATEMENTS_PER_SUBJECT],
                statement_from_sqlite_row,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        }
        Store::Postgres(postgres) => postgres
            .client()
            .await?
            .query(
                &format!(
                    "SELECT {STATEMENT_COLUMNS} FROM profile_statements
                     WHERE tenant_id = $1 AND subject = $2 ORDER BY statement_id LIMIT $3"
                ),
                &[&tenant_id, &subject, &MAX_STATEMENTS_PER_SUBJECT],
            )
            .await
            .map(|rows| rows.iter().map(statement_from_postgres_row).collect())
            .map_err(Into::into),
    }
}

pub(crate) async fn write_statement_state(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    record: &StatementRecord,
) -> Result<bool> {
    let changed = match store {
        Store::Sqlite(_) => store.sqlite_connection()?.execute(
            "UPDATE profile_statements
             SET epistemic_state = ?4, content = ?5, updated_at = ?6, confirmed_at = ?7,
                 resolved_at = ?8, superseded_by = ?9
             WHERE tenant_id = ?1 AND subject = ?2 AND statement_id = ?3",
            params![
                tenant_id,
                subject,
                record.statement_id,
                record.epistemic_state,
                record.content,
                record.updated_at,
                record.confirmed_at,
                record.resolved_at,
                record.superseded_by,
            ],
        )?,
        Store::Postgres(postgres) => {
            let changed = postgres
                .client()
                .await?
                .execute(
                    "UPDATE profile_statements
                     SET epistemic_state = $4, content = $5, updated_at = $6, confirmed_at = $7,
                         resolved_at = $8, superseded_by = $9
                     WHERE tenant_id = $1 AND subject = $2 AND statement_id = $3",
                    &[
                        &tenant_id,
                        &subject,
                        &record.statement_id,
                        &record.epistemic_state,
                        &record.content,
                        &record.updated_at,
                        &record.confirmed_at,
                        &record.resolved_at,
                        &record.superseded_by,
                    ],
                )
                .await?;
            usize::try_from(changed).unwrap_or(usize::MAX)
        }
    };
    Ok(changed > 0)
}

/// Forgetting is a deletion, not a state change. The row and its evidence stop existing.
pub(crate) async fn erase_statement(
    store: &Store,
    tenant_id: &str,
    subject: &str,
    statement_id: &str,
) -> Result<bool> {
    let removed = match store {
        Store::Sqlite(_) => store.sqlite_connection()?.execute(
            "DELETE FROM profile_statements
             WHERE tenant_id = ?1 AND subject = ?2 AND statement_id = ?3",
            params![tenant_id, subject, statement_id],
        )?,
        Store::Postgres(postgres) => {
            let removed = postgres
                .client()
                .await?
                .execute(
                    "DELETE FROM profile_statements
                     WHERE tenant_id = $1 AND subject = $2 AND statement_id = $3",
                    &[&tenant_id, &subject, &statement_id],
                )
                .await?;
            usize::try_from(removed).unwrap_or(usize::MAX)
        }
    };
    Ok(removed > 0)
}

struct ProfileSubject {
    tenant_id: String,
    subject: String,
}

async fn own_profile(
    state: &AppState,
    headers: &HeaderMap,
    audiences: &[&str],
) -> Result<ProfileSubject, HttpError> {
    let admitted = admitted_session_for_audiences(state, headers, audiences).await?;
    Ok(ProfileSubject {
        tenant_id: admitted.tenant_id,
        subject: admitted.subject,
    })
}

/// The person's durable view: every retained statement, its lifecycle, and why anything is
/// withheld from the projection. It is never returned under a projection audience.
async fn durable_response(state: &AppState, owner: &ProfileSubject) -> Result<Response, HttpError> {
    let consent = read_consent(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    let exclusions = read_exclusions(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    let statements = read_statements(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    let learning = consent.is_some_and(|consent| consent.learning);
    Ok(confidential_json(ProfileView {
        iss: state.config.issuer().to_owned(),
        dl_tenant: owner.tenant_id.clone(),
        sub: owner.subject.clone(),
        learning_consent: learning,
        consent_scope: LEARNING_CONSENT_SCOPE,
        consent_granted_at: consent.map(|consent| consent.granted_at),
        consent_revoked_at: consent.and_then(|consent| consent.revoked_at),
        excluded_sources: exclusions.iter().cloned().collect(),
        statements: statements
            .into_iter()
            .map(|record| {
                let reason = withheld_reason(&record, learning, &exclusions);
                RetainedStatementView {
                    statement_id: record.statement_id,
                    kind: record.kind,
                    horizon: record.horizon,
                    content: record.content,
                    epistemic_state: record.epistemic_state,
                    source_kind: record.source_kind,
                    source_reference: record.source_reference,
                    observed_at: record.observed_at,
                    created_at: record.created_at,
                    updated_at: record.updated_at,
                    confirmed_at: record.confirmed_at,
                    resolved_at: record.resolved_at,
                    superseded_by: record.superseded_by,
                    model_visible: reason.is_none(),
                    withheld_reason: reason,
                }
            })
            .collect(),
    }))
}

/// The only value a consumer ever receives.
async fn projection_response(
    state: &AppState,
    owner: &ProfileSubject,
) -> Result<Response, HttpError> {
    let consent = read_consent(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    let exclusions = read_exclusions(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    let statements = read_statements(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    Ok(confidential_json(project(
        state.config.issuer(),
        &owner.tenant_id,
        &owner.subject,
        consent,
        &exclusions,
        &statements,
    )))
}

pub(crate) async fn read_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    durable_response(&state, &owner).await
}

pub(crate) async fn read_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PROJECTION_AUDIENCES).await?;
    projection_response(&state, &owner).await
}

pub(crate) async fn put_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ConsentRequest>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    let exclusions = validated_exclusions(&request.excluded_sources)?;
    let known = read_consent(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?
        .is_some();
    {
        let _admission = if known {
            None
        } else {
            state
                .store
                .enforce_row_caps(&[RowCap {
                    sqlite_count: "SELECT count(*) FROM profile_consents WHERE tenant_id = ?1",
                    postgres_count:
                        "SELECT count(*)::BIGINT FROM profile_consents WHERE tenant_id = $1",
                    arguments: &[owner.tenant_id.as_str()],
                    maximum: MAX_PROFILE_CONSENTS,
                    label: "profile consents",
                }])
                .await?
        };
        write_consent(
            &state.store,
            &owner.tenant_id,
            &owner.subject,
            request.learning,
        )
        .await
        .map_err(HttpError::internal)?;
        replace_exclusions(&state.store, &owner.tenant_id, &owner.subject, &exclusions)
            .await
            .map_err(HttpError::internal)?;
    }
    durable_response(&state, &owner).await
}

pub(crate) async fn create_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StatementRequest>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PROJECTION_AUDIENCES).await?;
    let kind = validated_kind(&request.kind)?;
    let horizon = validated_horizon(&kind, request.horizon.as_deref())?;
    let statement_text = validated_content(&request.content)?;
    let (source_kind, source_reference) = validated_source(&request.source)?;
    let epistemic_state = validated_learned_state(&request.epistemic_state)?;

    let consent = read_consent(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    if !consent.is_some_and(|consent| consent.learning) {
        return Err(HttpError::forbidden(
            "retaining learning requires an active profile.learning consent",
        ));
    }
    let exclusions = read_exclusions(&state.store, &owner.tenant_id, &owner.subject)
        .await
        .map_err(HttpError::internal)?;
    if exclusions.contains(&source_reference) {
        return Err(HttpError::forbidden(
            "this source is excluded from profile learning",
        ));
    }
    let now = unix_time().map_err(HttpError::internal)?;
    let record = StatementRecord {
        statement_id: new_statement_id()?,
        kind,
        horizon,
        content: statement_text,
        epistemic_state,
        source_kind,
        source_reference,
        observed_at: now,
        created_at: now,
        updated_at: now,
        confirmed_at: None,
        resolved_at: None,
        superseded_by: None,
    };
    persist_new_statement(&state, &owner, &record).await?;
    // A learning consumer receives the projection it is allowed to see, never the durable store.
    projection_response(&state, &owner).await
}

fn new_statement_id() -> Result<String, HttpError> {
    Ok(format!(
        "{STATEMENT_ID_PREFIX}{}",
        random_token(16).map_err(HttpError::internal)?
    ))
}

async fn persist_new_statement(
    state: &AppState,
    owner: &ProfileSubject,
    record: &StatementRecord,
) -> Result<(), HttpError> {
    let _admission = state
        .store
        .enforce_row_caps(&[
            RowCap {
                sqlite_count:
                    "SELECT count(*) FROM profile_statements WHERE tenant_id = ?1 AND subject = ?2",
                postgres_count: "SELECT count(*)::BIGINT FROM profile_statements
                     WHERE tenant_id = $1 AND subject = $2",
                arguments: &[owner.tenant_id.as_str(), owner.subject.as_str()],
                maximum: MAX_STATEMENTS_PER_SUBJECT,
                label: "profile statements for one subject",
            },
            RowCap {
                sqlite_count: "SELECT count(*) FROM profile_statements WHERE tenant_id = ?1",
                postgres_count:
                    "SELECT count(*)::BIGINT FROM profile_statements WHERE tenant_id = $1",
                arguments: &[owner.tenant_id.as_str()],
                maximum: MAX_PROFILE_STATEMENTS,
                label: "profile statements",
            },
        ])
        .await?;
    write_statement(&state.store, &owner.tenant_id, &owner.subject, record)
        .await
        .map_err(HttpError::internal)
}

async fn own_statement(
    state: &AppState,
    owner: &ProfileSubject,
    statement_id: &str,
) -> Result<StatementRecord, HttpError> {
    read_statement(&state.store, &owner.tenant_id, &owner.subject, statement_id)
        .await
        .map_err(HttpError::internal)?
        .ok_or_else(|| HttpError::missing("no such statement in this profile"))
}

pub(crate) async fn confirm_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(statement_id): Path<String>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    let statement_id = validated_statement_id(&statement_id)?;
    let mut record = own_statement(&state, &owner, &statement_id).await?;
    if RESOLVED_STATES.contains(&record.epistemic_state.as_str()) {
        return Err(HttpError::unprocessable(
            "a withdrawn statement cannot be confirmed; make a correction instead",
        ));
    }
    let now = unix_time().map_err(HttpError::internal)?;
    CONFIRMED_STATE.clone_into(&mut record.epistemic_state);
    record.confirmed_at = Some(record.confirmed_at.unwrap_or(now));
    record.updated_at = now;
    apply_statement_state(&state, &owner, &record).await?;
    durable_response(&state, &owner).await
}

pub(crate) async fn revoke_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(statement_id): Path<String>,
    Json(request): Json<RevocationRequest>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    let statement_id = validated_statement_id(&statement_id)?;
    let state_name = validated_resolved_state(&request.epistemic_state)?;
    let mut record = own_statement(&state, &owner, &statement_id).await?;
    let now = unix_time().map_err(HttpError::internal)?;
    record.epistemic_state = state_name;
    record.resolved_at = Some(now);
    record.updated_at = now;
    apply_statement_state(&state, &owner, &record).await?;
    durable_response(&state, &owner).await
}

pub(crate) async fn correct_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(statement_id): Path<String>,
    Json(request): Json<CorrectionRequest>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    let statement_id = validated_statement_id(&statement_id)?;
    let mut previous = own_statement(&state, &owner, &statement_id).await?;
    let kind = match request.kind.as_deref() {
        Some(kind) => validated_kind(kind)?,
        None => previous.kind.clone(),
    };
    let horizon = match request.horizon.as_deref() {
        Some(horizon) => validated_horizon(&kind, Some(horizon))?,
        None if kind == previous.kind => previous.horizon.clone(),
        None => validated_horizon(&kind, None)?,
    };
    let content = validated_content(&request.content)?;
    let now = unix_time().map_err(HttpError::internal)?;
    let corrected = StatementRecord {
        statement_id: new_statement_id()?,
        kind,
        horizon,
        content,
        epistemic_state: CONFIRMED_STATE.to_owned(),
        source_kind: "person".to_owned(),
        source_reference: PERSON_SOURCE_REFERENCE.to_owned(),
        observed_at: now,
        created_at: now,
        updated_at: now,
        confirmed_at: Some(now),
        resolved_at: None,
        superseded_by: None,
    };
    persist_new_statement(&state, &owner, &corrected).await?;
    "revoked".clone_into(&mut previous.epistemic_state);
    previous.resolved_at = Some(now);
    previous.updated_at = now;
    previous.superseded_by = Some(corrected.statement_id.clone());
    apply_statement_state(&state, &owner, &previous).await?;
    durable_response(&state, &owner).await
}

pub(crate) async fn forget_statement(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(statement_id): Path<String>,
) -> Result<Response, HttpError> {
    let owner = own_profile(&state, &headers, &PERSON_CONTROL_AUDIENCES).await?;
    let statement_id = validated_statement_id(&statement_id)?;
    if !erase_statement(
        &state.store,
        &owner.tenant_id,
        &owner.subject,
        &statement_id,
    )
    .await
    .map_err(HttpError::internal)?
    {
        return Err(HttpError::missing("no such statement in this profile"));
    }
    durable_response(&state, &owner).await
}

async fn apply_statement_state(
    state: &AppState,
    owner: &ProfileSubject,
    record: &StatementRecord,
) -> Result<(), HttpError> {
    if write_statement_state(&state.store, &owner.tenant_id, &owner.subject, record)
        .await
        .map_err(HttpError::internal)?
    {
        return Ok(());
    }
    Err(HttpError::missing("no such statement in this profile"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        CONFIRMED_STATE, ConsentRecord, SourceRequest, StatementRecord, erase_statement, project,
        read_statement, read_statements, validated_content, validated_horizon, validated_kind,
        validated_learned_state, validated_source, write_statement, write_statement_state,
    };
    use crate::Store;

    const ISSUER: &str = "https://identity.example.test";
    const TENANT: &str = "tenant-dev";
    const SUBJECT: &str = "google-subject";

    fn granted_consent() -> ConsentRecord {
        ConsentRecord {
            learning: true,
            granted_at: 1_000,
            revoked_at: None,
        }
    }

    fn revoked_consent() -> ConsentRecord {
        ConsentRecord {
            learning: false,
            granted_at: 1_000,
            revoked_at: Some(2_000),
        }
    }

    fn statement(id: &str, state: &str, content: &str, source: &str) -> StatementRecord {
        StatementRecord {
            statement_id: format!("dl_profile_stmt_v1_{id}"),
            kind: "preference".to_owned(),
            horizon: None,
            content: content.to_owned(),
            epistemic_state: state.to_owned(),
            source_kind: source
                .split(':')
                .next()
                .unwrap_or("conversation")
                .to_owned(),
            source_reference: source.to_owned(),
            observed_at: 1_500,
            created_at: 1_500,
            updated_at: 1_500,
            confirmed_at: None,
            resolved_at: None,
            superseded_by: None,
        }
    }

    #[test]
    fn an_inferred_statement_never_reads_as_confirmed() {
        let inferred = statement(
            "aaaaaaaaaaaaaaaaaaaaaa",
            "inferred",
            "prefers asynchronous review",
            "conversation:thread-9",
        );
        let snapshot = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            std::slice::from_ref(&inferred),
        );
        let projected = &snapshot.statements[0];
        assert_eq!(projected.epistemic_state, "inferred");
        assert!(
            !projected.confirmed,
            "an inference must never present itself as a confirmation"
        );

        // The learning write path cannot name the confirmed state at all.
        assert!(validated_learned_state("confirmed").is_err());
        assert!(validated_learned_state("revoked").is_err());
        assert_eq!(validated_learned_state("Observed").unwrap(), "observed");

        // Only the person's confirmation moves it, and then it reads as confirmed.
        let mut confirmed = inferred;
        confirmed.epistemic_state = CONFIRMED_STATE.to_owned();
        confirmed.confirmed_at = Some(3_000);
        let snapshot = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            &[confirmed],
        );
        assert!(snapshot.statements[0].confirmed);
    }

    #[tokio::test]
    async fn revocation_removes_a_statement_from_the_projection() {
        let store = Store::in_memory().unwrap();
        let record = statement(
            "bbbbbbbbbbbbbbbbbbbbbb",
            CONFIRMED_STATE,
            "wants weekly written updates",
            "person:self",
        );
        write_statement(&store, TENANT, SUBJECT, &record)
            .await
            .unwrap();
        let retained = read_statements(&store, TENANT, SUBJECT).await.unwrap();
        assert_eq!(
            project(
                ISSUER,
                TENANT,
                SUBJECT,
                Some(granted_consent()),
                &BTreeSet::new(),
                &retained
            )
            .statement_count,
            1
        );

        let mut revoked_record = record.clone();
        revoked_record.epistemic_state = "revoked".to_owned();
        revoked_record.resolved_at = Some(4_000);
        assert!(
            write_statement_state(&store, TENANT, SUBJECT, &revoked_record)
                .await
                .unwrap()
        );

        let retained = read_statements(&store, TENANT, SUBJECT).await.unwrap();
        let snapshot = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            &retained,
        );
        assert_eq!(
            snapshot.statement_count, 0,
            "a revoked statement must leave the projection"
        );
        assert_eq!(
            retained[0].epistemic_state, "revoked",
            "the durable record keeps the withdrawal so it is not re-learned silently"
        );

        // Forgetting is stronger than revoking: the row stops existing.
        assert!(
            erase_statement(&store, TENANT, SUBJECT, &record.statement_id)
                .await
                .unwrap()
        );
        assert!(
            read_statement(&store, TENANT, SUBJECT, &record.statement_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn profile_learning_consent_is_independent_of_other_authority() {
        let retained = [statement(
            "cccccccccccccccccccccc",
            "observed",
            "works in short focused blocks",
            "workflow_run:run-4",
        )];

        // No consent record at all: nothing is projected.
        let absent = project(ISSUER, TENANT, SUBJECT, None, &BTreeSet::new(), &retained);
        assert!(!absent.learning_consent);
        assert_eq!(absent.statement_count, 0);

        // Granted: projected. Revoked: empty again, without touching the durable rows.
        assert_eq!(
            project(
                ISSUER,
                TENANT,
                SUBJECT,
                Some(granted_consent()),
                &BTreeSet::new(),
                &retained
            )
            .statement_count,
            1
        );
        let withdrawn = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(revoked_consent()),
            &BTreeSet::new(),
            &retained,
        );
        assert!(!withdrawn.learning_consent);
        assert_eq!(withdrawn.statement_count, 0);

        // The consent scope is not a Connector scope and grants no audience.
        assert_eq!(super::LEARNING_CONSENT_SCOPE, "profile.learning");
        assert!(!crate::CONNECTORS_SCOPES.contains(&super::LEARNING_CONSENT_SCOPE));
        assert_ne!(super::PROFILE_AUDIENCE, crate::CONNECTORS_AUDIENCE);
        assert_ne!(super::PROFILE_AUDIENCE, crate::STATUS_AUDIENCE);
    }

    #[test]
    fn a_learning_consumer_cannot_address_the_durable_store() {
        // The projection and the learning write are reachable from a consumer audience; the
        // durable view and every lifecycle control are not.
        assert!(super::PROJECTION_AUDIENCES.contains(&super::PROFILE_PROJECTION_AUDIENCE));
        assert!(
            !super::PERSON_CONTROL_AUDIENCES.contains(&super::PROFILE_PROJECTION_AUDIENCE),
            "a consumer audience must not reach the durable profile or its controls"
        );
        // The person can always see exactly what a consumer is given.
        assert!(super::PROJECTION_AUDIENCES.contains(&super::PROFILE_AUDIENCE));
        assert!(super::PERSON_CONTROL_AUDIENCES.contains(&super::PROFILE_AUDIENCE));
        assert_ne!(super::PROFILE_AUDIENCE, super::PROFILE_PROJECTION_AUDIENCE);
    }

    #[test]
    fn a_secret_shaped_value_is_refused_entry_to_a_projection() {
        for smuggled in [
            "the deployment password=hunter2 lives in the runbook",
            "session dl_session_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is mine",
            "uses ghp_16CharactersOrMoreOfOpaqueMaterial for the mirror",
        ] {
            assert!(
                validated_content(smuggled).is_err(),
                "write path admitted {smuggled}"
            );
        }
        assert!(
            validated_source(&SourceRequest {
                kind: "datasource".to_owned(),
                id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            })
            .is_err()
        );

        // A row that reached the database by some other route is still screened at projection.
        let smuggled = statement(
            "dddddddddddddddddddddd",
            "observed",
            "the token is xoxb-11111111-2222222222-aBcDeFgHiJkLmNoPqRsTuVwX",
            "conversation:thread-1",
        );
        let snapshot = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            std::slice::from_ref(&smuggled),
        );
        assert_eq!(
            snapshot.statement_count, 0,
            "the projection must re-screen durable rows"
        );
        assert_eq!(
            super::withheld_reason(&smuggled, true, &BTreeSet::new()),
            Some("the retained value is credential-shaped")
        );
    }

    #[test]
    fn excluded_datasource_content_cannot_enter_the_projection() {
        let retained = [statement(
            "eeeeeeeeeeeeeeeeeeeeee",
            "inferred",
            "reads the incident channel every morning",
            "datasource:slack-incidents",
        )];
        let mut exclusions = BTreeSet::new();
        exclusions.insert("datasource:slack-incidents".to_owned());
        assert_eq!(
            project(
                ISSUER,
                TENANT,
                SUBJECT,
                Some(granted_consent()),
                &exclusions,
                &retained
            )
            .statement_count,
            0
        );
        assert_eq!(
            project(
                ISSUER,
                TENANT,
                SUBJECT,
                Some(granted_consent()),
                &BTreeSet::new(),
                &retained
            )
            .statement_count,
            1
        );
    }

    #[test]
    fn a_snapshot_is_immutable_and_identified_by_its_content() {
        let retained = [statement(
            "ffffffffffffffffffffff",
            "observed",
            "prefers a written brief before a call",
            "conversation:thread-2",
        )];
        let first = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            &retained,
        );
        let again = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            &retained,
        );
        assert_eq!(first, again);
        assert!(first.snapshot_id.starts_with("dl_profile_snapshot_v1_"));
        assert!(first.model_visible);

        let mut changed = retained.clone();
        changed[0].epistemic_state = CONFIRMED_STATE.to_owned();
        let promoted = project(
            ISSUER,
            TENANT,
            SUBJECT,
            Some(granted_consent()),
            &BTreeSet::new(),
            &changed,
        );
        assert_ne!(first.snapshot_id, promoted.snapshot_id);
        assert_ne!(
            first.snapshot_id,
            project(
                ISSUER,
                "other-tenant",
                SUBJECT,
                Some(granted_consent()),
                &BTreeSet::new(),
                &retained
            )
            .snapshot_id
        );
    }

    #[tokio::test]
    async fn a_profile_row_is_bound_to_its_tenant_and_subject() {
        let store = Store::in_memory().unwrap();
        let record = statement(
            "gggggggggggggggggggggg",
            "observed",
            "prefers morning reviews",
            "conversation:thread-3",
        );
        write_statement(&store, TENANT, SUBJECT, &record)
            .await
            .unwrap();
        assert!(
            read_statement(&store, TENANT, "another-subject", &record.statement_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            read_statement(&store, "other-tenant", SUBJECT, &record.statement_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !erase_statement(&store, TENANT, "another-subject", &record.statement_id)
                .await
                .unwrap()
        );
    }

    /// Builds a configuration equivalent to the deployed one-tenant slice.
    fn config() -> crate::Config {
        crate::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_origin: url::Url::parse("https://identity.example.test/").unwrap(),
            connectors_endpoint: None,
            tenant_id: TENANT.to_owned(),
            cli_client_id: "daemonloom-harness-cli".to_owned(),
            web_clients: Vec::new(),
            upstream_issuer: "https://accounts.example.test".to_owned(),
            upstream_client_id: "upstream-client".to_owned(),
            upstream_client_secret: crate::SecretValue::new("not-a-real-secret".to_owned()),
            organization_domain_policy: crate::OrganizationDomainPolicy::default(),
            static_group_memberships: crate::StaticGroupMemberships::new(vec![(
                TENANT.to_owned(),
                "person@example.test".to_owned(),
                vec!["operator".to_owned()],
            )])
            .unwrap(),
            database_url: None,
            database_path: std::path::PathBuf::new(),
        }
    }

    #[tokio::test]
    async fn granting_or_revoking_learning_consent_moves_no_other_authority() {
        let store = Store::in_memory().unwrap();
        let config = config();
        let identity = crate::Identity {
            subject: SUBJECT.to_owned(),
            email: Some("person@example.test".to_owned()),
        };
        let credential = format!("dl_session_v1_{}", "a".repeat(43));
        store
            .put_session(&credential, &config, &identity)
            .await
            .unwrap();

        let admitted = store
            .resolve_session(&credential, &config)
            .await
            .unwrap()
            .unwrap();
        let authority_before = config
            .static_group_memberships
            .groups_for(&admitted.tenant_id, admitted.email.as_deref());

        super::write_consent(&store, TENANT, SUBJECT, true)
            .await
            .unwrap();
        let admitted = store
            .resolve_session(&credential, &config)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            config
                .static_group_memberships
                .groups_for(&admitted.tenant_id, admitted.email.as_deref()),
            authority_before,
            "granting profile-learning consent must not change an authority group"
        );
        assert_eq!(
            crate::bootstrap_connector_scope("connectors.catalog.read").unwrap(),
            "connectors.catalog.read"
        );
        assert!(
            crate::bootstrap_connector_scope("connectors.invoke").is_err(),
            "consent must not widen the admitted Connector scope"
        );

        // Revoking learning empties the projection and leaves the session, its groups, and the
        // durable rows exactly as they were.
        let record = statement(
            "hhhhhhhhhhhhhhhhhhhhhh",
            "observed",
            "reviews in the afternoon",
            "conversation:thread-7",
        );
        write_statement(&store, TENANT, SUBJECT, &record)
            .await
            .unwrap();
        super::write_consent(&store, TENANT, SUBJECT, false)
            .await
            .unwrap();
        let consent = super::read_consent(&store, TENANT, SUBJECT).await.unwrap();
        let retained = read_statements(&store, TENANT, SUBJECT).await.unwrap();
        assert_eq!(retained.len(), 1, "revoking consent must not destroy data");
        assert_eq!(
            project(
                ISSUER,
                TENANT,
                SUBJECT,
                consent,
                &BTreeSet::new(),
                &retained
            )
            .statement_count,
            0
        );
        let admitted = store.resolve_session(&credential, &config).await.unwrap();
        assert!(
            admitted.is_some(),
            "revoking profile-learning consent must not revoke the session"
        );
        assert_eq!(
            config
                .static_group_memberships
                .groups_for(TENANT, Some("person@example.test")),
            authority_before
        );
    }

    #[test]
    fn statement_vocabulary_is_closed() {
        assert_eq!(validated_kind(" Preference ").unwrap(), "preference");
        assert!(validated_kind("belief").is_err());
        assert_eq!(
            validated_horizon("goal_horizon", Some("long_term")).unwrap(),
            Some("long_term".to_owned())
        );
        assert!(validated_horizon("goal_horizon", None).is_err());
        assert!(validated_horizon("goal_horizon", Some("someday")).is_err());
        assert!(validated_horizon("preference", Some("long_term")).is_err());
        assert_eq!(validated_horizon("friction", None).unwrap(), None);

        assert_eq!(
            validated_source(&SourceRequest {
                kind: "Datasource".to_owned(),
                id: "gitlab-merge-requests".to_owned(),
            })
            .unwrap(),
            (
                "datasource".to_owned(),
                "datasource:gitlab-merge-requests".to_owned()
            )
        );
        assert!(
            validated_source(&SourceRequest {
                kind: "telepathy".to_owned(),
                id: "abc".to_owned(),
            })
            .is_err()
        );
        assert!(validated_content(&"a".repeat(513)).is_err());
        assert!(validated_content("  ").is_err());
    }
}
