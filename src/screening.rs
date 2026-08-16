//! Deterministic refusal of credential-shaped material in personal profile content.
//!
//! A profile statement is user data, not a credential. The profile projection is handed to a
//! replaceable model worker, so any secret that reaches a statement would leave the process inside
//! ordinary prose. This screen is applied twice: once when a statement is written, so the request
//! is refused with the material never durable, and once when a snapshot is built, so a row that
//! reached the database by some other route still cannot enter a projection.
//!
//! The screen is intentionally conservative and deterministic. It never inspects entropy
//! statistically; it recognizes named credential markers, vendor prefixes, `JSON` Web Token shape,
//! `URL` user information, and long mixed-class opaque tokens.

/// Substrings that name a credential regardless of the value that follows them. Compared against
/// an ASCII-lowercased copy of the candidate.
const CREDENTIAL_MARKERS: [&str; 14] = [
    "-----begin ",
    "api-key=",
    "api_key=",
    "apikey=",
    "authorization: bearer ",
    "client_secret",
    "passwd=",
    "password=",
    "private_key",
    "secret=",
    "secret_key",
    "session=dl_",
    "token=",
    "x-api-key",
];

/// Vendor credential prefixes, compared case-sensitively against an opaque token.
const CREDENTIAL_PREFIXES: [&str; 18] = [
    "AIza",
    "AKIA",
    "ASIA",
    "dl_access_v1_",
    "dl_session_v1_",
    "ghp_",
    "gho_",
    "ghr_",
    "ghs_",
    "ghu_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "xapp-",
    "xoxa-",
    "xoxb-",
    "xoxp-",
];

/// The shortest opaque token treated as possible key material.
const OPAQUE_TOKEN_FLOOR: usize = 32;

/// The shortest plausible `JSON` Web Token segment.
const JWT_SEGMENT_FLOOR: usize = 8;

/// Reports why a value is credential-shaped, or `None` when it may be retained.
///
/// The returned reason is a fixed string. It never contains any part of the inspected value, so it
/// is safe to return to the caller and to log.
pub(crate) fn secret_shape(value: &str) -> Option<&'static str> {
    let lowered = value.to_ascii_lowercase();
    if CREDENTIAL_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
    {
        return Some("a named credential marker");
    }
    if contains_url_user_information(&lowered) {
        return Some("URL user information");
    }
    if tokens(value, is_dotted_token_byte).any(is_json_web_token) {
        return Some("JSON Web Token shape");
    }
    tokens(value, is_opaque_token_byte).find_map(|token| {
        if CREDENTIAL_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            Some("a vendor credential prefix")
        } else if is_opaque_key_material(token) {
            Some("a long mixed-class opaque token")
        } else {
            None
        }
    })
}

fn tokens(value: &str, admitted: fn(u8) -> bool) -> impl Iterator<Item = &str> {
    value
        .split(move |character: char| !u8::try_from(u32::from(character)).is_ok_and(admitted))
        .filter(|token| !token.is_empty())
}

fn is_dotted_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn is_opaque_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// A base64url token of at least [`OPAQUE_TOKEN_FLOOR`] characters that mixes upper case, lower
/// case, and digits. A lowercase hexadecimal content digest and ordinary prose both fall outside
/// this shape, so provenance references such as `sha256:<digest>` remain expressible.
fn is_opaque_key_material(token: &str) -> bool {
    if token.len() < OPAQUE_TOKEN_FLOOR {
        return false;
    }
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    for byte in token.bytes() {
        match byte {
            b'A'..=b'Z' => upper = true,
            b'a'..=b'z' => lower = true,
            b'0'..=b'9' => digit = true,
            _ => {}
        }
    }
    upper && lower && digit
}

fn is_json_web_token(token: &str) -> bool {
    let mut segments = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    header.starts_with("eyJ")
        && [header, payload, signature].iter().all(|segment| {
            segment.len() >= JWT_SEGMENT_FLOOR
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

/// Detects `scheme://user:password@host`, which carries a password even when the password itself
/// is short and unremarkable.
fn contains_url_user_information(lowered: &str) -> bool {
    lowered.match_indices("://").any(|(index, separator)| {
        lowered[index + separator.len()..]
            .split(|character: char| {
                matches!(character, '/' | '?' | '#') || character.is_whitespace()
            })
            .next()
            .and_then(|authority| authority.split_once('@'))
            .is_some_and(|(user_information, _)| user_information.contains(':'))
    })
}

#[cfg(test)]
mod tests {
    use super::secret_shape;

    #[test]
    fn ordinary_personal_statements_are_retained() {
        for statement in [
            "prefers short pull request descriptions",
            "is blocked by the flaky integration suite on Mondays",
            "wants the migration finished before the end of the quarter",
            "reviewed evidence sha256:9f2c4a1b6d8e0f3a5c7b9d1e2f4a6c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0a",
            "uses example.com and 127.0.0.1:8080 during local work",
        ] {
            assert_eq!(secret_shape(statement), None, "refused {statement}");
        }
    }

    #[test]
    fn credential_shaped_values_are_refused() {
        // Assembled at run time so that this fixture is not itself a committed token literal that
        // the repository's own history secret scan would have to be told to ignore.
        let json_web_token = format!(
            "id token {}{}{}",
            "eyJhbGciOiJIUzI1NiJ9",
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        let refused = [
            "the deployment password=hunter2 is in the runbook",
            "carries Authorization: Bearer abc",
            "-----BEGIN RSA PRIVATE KEY-----",
            "note the key AKIAIOSFODNN7EXAMPLE for the bucket",
            "slack app uses xoxb-11111111-2222222222-aBcDeFgHiJkLmNoPqRsTuVwX",
            "github token ghp_16CharactersOrMoreOfOpaqueMaterial",
            "session dl_session_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "connects to postgres://identity:letmein@db.internal/identity",
            json_web_token.as_str(),
            "the value bXlWZXJ5U2VjcmV0VmFsdWU5OTk5OTk5OTk5OTk5OTk5 was copied",
        ];
        for statement in refused {
            assert!(
                secret_shape(statement).is_some(),
                "retained credential-shaped {statement}"
            );
        }
    }

    #[test]
    fn refusal_reasons_never_echo_the_inspected_value() {
        let reason = secret_shape("password=hunter2").unwrap();
        assert!(!reason.contains("hunter2"));
    }
}
