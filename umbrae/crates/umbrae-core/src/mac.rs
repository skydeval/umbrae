//! Commit and record MACs (spec: "Requesting a MAC", "Commit MAC",
//! "Record MAC").
//!
//! A MAC is an RFC 9421 signature with `hmac-sha256`, keyed by the
//! per-request shared secret ([`crate::kem`]). The syncer asks for one with
//! `Accept-Signature`, naming its key share as `keyid` and the profile as
//! `tag`. The host answers with the covered header (`Atproto-Space-Commit`
//! or `Atproto-Space-Record`), `Signature-Input` under the requested label
//! and parameters, and `Signature`, and lists `Accept-Signature` in `Vary`.
//!
//! The covered header is flagged `sf`: it's signed in its re-serialized
//! form, so whitespace differences don't matter. A MAC proves nothing to a
//! third party, since the syncer could have computed it itself.

use crate::cid::Cid;
use crate::commit::Commit;
use crate::didkey;
use crate::httpsig::{
    covers_exactly, find_signature, key, members_with_tag, parse_dict, serialize_dict,
    serialize_inner_list, sf_string, signature_base, signature_field, signature_params, Component,
    Requirements, SignatureError,
};
use crate::kem::Encapsulation;
use crate::uri::SpaceRecordUri;
use hmac::{Hmac, Mac};
use sfv::{DictSerializer, ListEntry};
use sha2::Sha256;

/// The only MAC algorithm.
pub const MAC_ALG: &str = "hmac-sha256";
const MAC_LABEL: &str = "mac";
/// The parameters a host fulfils. A fresh key share per request makes
/// `created`, `expires` and `nonce` pointless, so they're refused.
const REQUEST_PARAMS: &[&str] = &["keyid", "tag", "alg"];

/// Which response a MAC covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProfile {
    /// `getLatestCommit`, `getRepo`, `listRepoOps`.
    Commit,
    /// `getRecord`.
    Record,
}

impl MacProfile {
    /// The profile's tag, which is also its covered header's name.
    pub fn tag(self) -> &'static str {
        match self {
            MacProfile::Commit => "atproto-space-commit",
            MacProfile::Record => "atproto-space-record",
        }
    }

    /// The covered header (lowercase).
    pub fn header(self) -> &'static str {
        self.tag()
    }

    fn components(self) -> [Component; 1] {
        [Component {
            name: self.header(),
            sf: true,
        }]
    }
}

/// The syncer's `Accept-Signature` value, e.g.
/// `mac=("atproto-space-commit";sf);keyid="did:key:zDna…";tag="atproto-space-commit"`.
pub fn format_mac_request(profile: MacProfile, key_share: &str) -> String {
    let params = signature_params(
        &profile.components(),
        &[("keyid", key_share), ("tag", profile.tag())],
    );
    format!("{MAC_LABEL}={params}")
}

/// A MAC request as the host reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacRequest {
    /// The label to answer under.
    pub label: String,
    /// The syncer's key share, a P-256 `did:key`.
    pub key_share: String,
    /// The requested parameters, serialized; the MAC uses them as given.
    pub signature_params: String,
}

/// Find the MAC requested for `profile` in `Accept-Signature`. Requests
/// with other tags are ignored, so this is `None` when none is for the
/// profile (or the header is absent); a host that requires a MAC turns that
/// into an error.
pub fn parse_mac_request(
    accept_signature: Option<&str>,
    profile: MacProfile,
) -> Result<Option<MacRequest>, SignatureError> {
    let Some(value) = accept_signature else {
        return Ok(None);
    };
    let dict = parse_dict(value)?;
    let tagged = members_with_tag(&dict, profile.tag());
    if tagged.len() > 1 {
        return Err(SignatureError::MultipleTagged);
    }
    let Some(&(label, list)) = tagged.first() else {
        return Ok(None);
    };
    if !covers_exactly(list, &profile.components()) {
        return Err(SignatureError::Components);
    }
    for name in list.params.keys() {
        if !REQUEST_PARAMS.contains(&name.as_str()) {
            return Err(SignatureError::UnsupportedParameter(
                name.as_str().to_owned(),
            ));
        }
    }
    if let Some(alg) = list.params.get("alg") {
        if alg.as_string().map(|s| s.as_str()) != Some(MAC_ALG) {
            return Err(SignatureError::Algorithm);
        }
    }
    let key_share = list
        .params
        .get("keyid")
        .and_then(|k| k.as_string())
        .map(|s| s.as_str())
        .filter(|k| didkey::is_p256(k))
        .ok_or(SignatureError::InvalidKey)?;
    Ok(Some(MacRequest {
        label: label.to_owned(),
        key_share: key_share.to_owned(),
        signature_params: serialize_inner_list(list),
    }))
}

/// The response headers a host adds for a MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacHeaders {
    /// The covered header's name (lowercase) and value.
    pub covered_name: &'static str,
    pub covered_value: String,
    pub signature_input: String,
    pub signature: String,
}

fn hmac(secret: &[u8; 32], base: &[u8]) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(base);
    m
}

fn mac_headers(
    profile: MacProfile,
    covered: String,
    req: &MacRequest,
    secret: &[u8; 32],
) -> MacHeaders {
    let base = signature_base(&profile.components(), &[&covered], &req.signature_params);
    let tag = hmac(secret, &base).finalize().into_bytes();
    MacHeaders {
        covered_name: profile.header(),
        covered_value: covered,
        signature_input: format!("{}={}", req.label, req.signature_params),
        signature: signature_field(&req.label, &tag),
    }
}

/// Host side: the MAC headers for a commit response.
pub fn commit_mac_headers(commit: &Commit, req: &MacRequest, secret: &[u8; 32]) -> MacHeaders {
    mac_headers(MacProfile::Commit, commit.header(), req, secret)
}

/// The `Atproto-Space-Record` value: `uri="at:space/…", cid="bafyrei…"`.
pub fn record_header(uri: &SpaceRecordUri, cid: &Cid) -> String {
    let (uri, cid) = (uri.to_string(), cid.to_string());
    let mut ser = DictSerializer::new();
    let _ = ser.bare_item(key("uri"), sf_string(&uri));
    let _ = ser.bare_item(key("cid"), sf_string(&cid));
    ser.finish().expect("two members")
}

/// Host side: the MAC headers for a `getRecord` response.
pub fn record_mac_headers(
    uri: &SpaceRecordUri,
    cid: &Cid,
    req: &MacRequest,
    secret: &[u8; 32],
) -> MacHeaders {
    mac_headers(MacProfile::Record, record_header(uri, cid), req, secret)
}

/// The response fields a syncer checks a MAC with.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacFields<'a> {
    pub covered: Option<&'a str>,
    pub signature_input: Option<&'a str>,
    pub signature: Option<&'a str>,
}

/// Check the MAC for `profile`; on success, return the covered header in
/// its normalized (re-serialized) form.
fn verify_mac(
    profile: MacProfile,
    enc: &Encapsulation,
    fields: &MacFields<'_>,
) -> Result<String, SignatureError> {
    let components = profile.components();
    let found = find_signature(
        fields.signature_input,
        fields.signature,
        &Requirements {
            tag: profile.tag(),
            components: &components,
            alg: MAC_ALG,
            key_id: &enc.key_share,
        },
    )?;
    let covered = fields
        .covered
        .ok_or(SignatureError::MissingField(profile.header()))?;
    let normalized = serialize_dict(&parse_dict(covered)?)?;
    let base = signature_base(&components, &[&normalized], &found.signature_params);
    hmac(&enc.shared_secret, &base)
        .verify_slice(&found.signature)
        .map_err(|_| SignatureError::Invalid)?;
    Ok(normalized)
}

/// Syncer side: verify a commit response's MAC, and that the header it
/// covers describes `commit`. Separately check the commit is for the
/// requested repo and space ([`Commit::check_for`]).
pub fn verify_commit_mac(
    commit: &Commit,
    enc: &Encapsulation,
    fields: &MacFields<'_>,
) -> Result<(), SignatureError> {
    let covered = verify_mac(MacProfile::Commit, enc, fields)?;
    commit
        .check_header(&covered)
        .map_err(|_| SignatureError::CoveredMismatch)
}

/// Syncer side: verify a `getRecord` response's MAC, and that the header it
/// covers names `uri` and `cid`. The caller computes `cid` from the
/// returned record and checks `uri` is the one requested.
pub fn verify_record_mac(
    uri: &SpaceRecordUri,
    cid: &Cid,
    enc: &Encapsulation,
    fields: &MacFields<'_>,
) -> Result<(), SignatureError> {
    let covered = verify_mac(MacProfile::Record, enc, fields)?;
    let dict = parse_dict(&covered)?;
    let text = |k: &str| match dict.get(k) {
        Some(ListEntry::Item(i)) => i.bare_item.as_string().map(|s| s.as_str().to_owned()),
        _ => None,
    };
    if text("uri") == Some(uri.to_string()) && text("cid") == Some(cid.to_string()) {
        Ok(())
    } else {
        Err(SignatureError::CoveredMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem;
    use crate::uri::SpaceRef;
    use p256::SecretKey;
    use rand_core::OsRng;

    const SPACE: &str = "at:space/did:example:space/app.bsky.group/test";
    const REV: &str = "3kbcq3p7ad422";

    fn commit() -> Commit {
        Commit::from_parts(
            1,
            "did:example:alice",
            SpaceRef::parse(SPACE).unwrap(),
            REV,
            [1; 32],
        )
        .unwrap()
    }

    /// A syncer's encapsulation against a fresh author key, and the host's
    /// view of the same request.
    fn setup(profile: MacProfile) -> (Encapsulation, MacRequest, [u8; 32]) {
        let author = SecretKey::random(&mut OsRng);
        let enc = kem::encapsulate(&didkey::format_p256(&author.public_key())).unwrap();
        let req = parse_mac_request(Some(&format_mac_request(profile, &enc.key_share)), profile)
            .unwrap()
            .unwrap();
        let host_secret = kem::decapsulate(&author, &req.key_share).unwrap();
        (enc, req, host_secret)
    }

    fn fields(h: &MacHeaders) -> MacFields<'_> {
        MacFields {
            covered: Some(&h.covered_value),
            signature_input: Some(&h.signature_input),
            signature: Some(&h.signature),
        }
    }

    #[test]
    fn request_format_and_round_trip() {
        let ks = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let header = format_mac_request(MacProfile::Commit, ks);
        assert_eq!(
            header,
            format!(
                "mac=(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"atproto-space-commit\""
            )
        );
        assert_eq!(
            format_mac_request(MacProfile::Record, ks),
            format!(
                "mac=(\"atproto-space-record\";sf);keyid=\"{ks}\";tag=\"atproto-space-record\""
            )
        );
        let req = parse_mac_request(Some(&header), MacProfile::Commit)
            .unwrap()
            .unwrap();
        assert_eq!(req.label, "mac");
        assert_eq!(req.key_share, ks);
        assert_eq!(req.signature_params, header["mac=".len()..]);
    }

    #[test]
    fn request_found_by_tag_under_any_label() {
        let ks = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let header = format!(
            "other=(\"content-digest\");tag=\"other\", m=(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"atproto-space-commit\""
        );
        let req = parse_mac_request(Some(&header), MacProfile::Commit)
            .unwrap()
            .unwrap();
        assert_eq!(req.label, "m");
        // Other profiles' requests are ignored.
        let rec = format_mac_request(MacProfile::Record, ks);
        assert_eq!(parse_mac_request(Some(&rec), MacProfile::Commit), Ok(None));
        assert_eq!(parse_mac_request(None, MacProfile::Commit), Ok(None));
    }

    #[test]
    fn request_rejections() {
        let ks = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let good = format_mac_request(MacProfile::Commit, ks);
        let p = MacProfile::Commit;
        assert_eq!(
            parse_mac_request(Some("???"), p),
            Err(SignatureError::Malformed)
        );
        let req =
            format!("(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"atproto-space-commit\"");
        assert_eq!(
            parse_mac_request(Some(&format!("a={req}, b={req}")), p),
            Err(SignatureError::MultipleTagged)
        );
        assert!(parse_mac_request(Some(&format!("{good};alg=\"hmac-sha256\"")), p).is_ok());
        assert_eq!(
            parse_mac_request(Some(&format!("{good};alg=\"ecdsa-p256-sha256\"")), p),
            Err(SignatureError::Algorithm)
        );
        for extra in ["created=1", "expires=2", "nonce=\"abc\""] {
            assert!(
                matches!(
                    parse_mac_request(Some(&format!("{good};{extra}")), p),
                    Err(SignatureError::UnsupportedParameter(_))
                ),
                "{extra}"
            );
        }
        for components in [
            "(\"atproto-space-record\";sf)",
            "(\"atproto-space-commit\")",
            "(\"atproto-space-commit\";sf \"authorization\")",
        ] {
            let h = format!("mac={components};keyid=\"{ks}\";tag=\"atproto-space-commit\"");
            assert_eq!(
                parse_mac_request(Some(&h), p),
                Err(SignatureError::Components)
            );
        }
        for keyid in ["", ";keyid=\"not-a-did\"", ";keyid=\"did:web:example.com\""] {
            let h =
                format!("mac=(\"atproto-space-commit\";sf){keyid};tag=\"atproto-space-commit\"");
            assert_eq!(
                parse_mac_request(Some(&h), p),
                Err(SignatureError::InvalidKey)
            );
        }
    }

    #[test]
    fn commit_mac_matches_the_rfc9421_base() {
        let (enc, req, host_secret) = setup(MacProfile::Commit);
        assert_eq!(host_secret, enc.shared_secret);
        let h = commit_mac_headers(&commit(), &req, &host_secret);
        assert_eq!(h.covered_name, "atproto-space-commit");
        assert_eq!(h.covered_value, commit().header());
        assert_eq!(h.signature_input, format!("mac={}", req.signature_params));
        // Recompute the HMAC over the base the spec describes.
        let base = format!(
            "\"atproto-space-commit\";sf: {}\n\"@signature-params\": {}",
            h.covered_value, req.signature_params
        );
        let tag = hmac(&enc.shared_secret, base.as_bytes())
            .finalize()
            .into_bytes();
        assert_eq!(h.signature, signature_field("mac", &tag));
        verify_commit_mac(&commit(), &enc, &fields(&h)).unwrap();
    }

    #[test]
    fn commit_mac_rejections() {
        let (enc, req, host_secret) = setup(MacProfile::Commit);
        let h = commit_mac_headers(&commit(), &req, &host_secret);
        // Another shared secret.
        let other = commit_mac_headers(&commit(), &req, &[9; 32]);
        assert_eq!(
            verify_commit_mac(&commit(), &enc, &fields(&other)),
            Err(SignatureError::Invalid)
        );
        // Another commit than the one the header covers.
        let c2 = Commit::from_parts(
            1,
            "did:example:bob",
            SpaceRef::parse(SPACE).unwrap(),
            REV,
            [1; 32],
        )
        .unwrap();
        assert_eq!(
            verify_commit_mac(&c2, &enc, &fields(&h)),
            Err(SignatureError::CoveredMismatch)
        );
        // A tampered header.
        let tampered = h.covered_value.replace(REV, "3kbcq3p7ad423");
        let f = MacFields {
            covered: Some(&tampered),
            ..fields(&h)
        };
        assert_eq!(
            verify_commit_mac(&commit(), &enc, &f),
            Err(SignatureError::Invalid)
        );
        // Missing pieces.
        for which in 0..3 {
            let mut f = fields(&h);
            match which {
                0 => f.covered = None,
                1 => f.signature_input = None,
                _ => f.signature = None,
            }
            assert!(verify_commit_mac(&commit(), &enc, &f).is_err());
        }
    }

    #[test]
    fn commit_mac_normalizes_whitespace_and_labels() {
        let (enc, req, host_secret) = setup(MacProfile::Commit);
        let h = commit_mac_headers(&commit(), &req, &host_secret);
        let spaced = h.covered_value.replace(", ", ",   ");
        let f = MacFields {
            covered: Some(&spaced),
            ..fields(&h)
        };
        verify_commit_mac(&commit(), &enc, &f).unwrap();
        let si = h.signature_input.replacen("mac=", "other=", 1);
        let sg = h.signature.replacen("mac=", "other=", 1);
        let f = MacFields {
            covered: Some(&h.covered_value),
            signature_input: Some(&si),
            signature: Some(&sg),
        };
        verify_commit_mac(&commit(), &enc, &f).unwrap();
        // Two MACs with the tag.
        let si2 = format!("{}, {si}", h.signature_input);
        let sg2 = format!("{}, {sg}", h.signature);
        let f = MacFields {
            covered: Some(&h.covered_value),
            signature_input: Some(&si2),
            signature: Some(&sg2),
        };
        assert_eq!(
            verify_commit_mac(&commit(), &enc, &f),
            Err(SignatureError::MultipleTagged)
        );
    }

    #[test]
    fn commit_mac_parameter_checks() {
        let (enc, _, _) = setup(MacProfile::Commit);
        let c = commit();
        // A host answering with its own parameters: the MAC covers them as sent.
        let with = |params: &str| {
            let covered = c.header();
            let base =
                format!("\"atproto-space-commit\";sf: {covered}\n\"@signature-params\": {params}");
            let tag = hmac(&enc.shared_secret, base.as_bytes())
                .finalize()
                .into_bytes();
            (
                covered,
                format!("mac={params}"),
                signature_field("mac", &tag),
            )
        };
        let ks = &enc.key_share;
        for params in [
            format!("(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\";created=1700000000;keyid=\"{ks}\""),
            "(\"atproto-space-commit\";sf);tag=\"atproto-space-commit\"".to_owned(),
            format!("(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"atproto-space-commit\";alg=\"hmac-sha256\""),
        ] {
            let (cv, si, sg) = with(&params);
            let f = MacFields {
                covered: Some(&cv),
                signature_input: Some(&si),
                signature: Some(&sg),
            };
            verify_commit_mac(&c, &enc, &f).unwrap_or_else(|e| panic!("{params}: {e}"));
        }
        for (params, err) in [
            (
                "(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaOther\";tag=\"atproto-space-commit\"".to_owned(),
                SignatureError::KeyIdMismatch,
            ),
            (
                format!("(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"atproto-space-commit\";alg=\"hmac-sha512\""),
                SignatureError::Algorithm,
            ),
            (
                format!("(\"atproto-space-commit\";sf);keyid=\"{ks}\";tag=\"other\""),
                SignatureError::MissingTagged,
            ),
            (
                format!("(\"atproto-space-commit\");keyid=\"{ks}\";tag=\"atproto-space-commit\""),
                SignatureError::Components,
            ),
        ] {
            let (cv, si, sg) = with(&params);
            let f = MacFields {
                covered: Some(&cv),
                signature_input: Some(&si),
                signature: Some(&sg),
            };
            assert_eq!(verify_commit_mac(&c, &enc, &f), Err(err), "{params}");
        }
    }

    #[test]
    fn record_mac() {
        let (enc, req, host_secret) = setup(MacProfile::Record);
        let uri = SpaceRecordUri::parse(&format!(
            "{SPACE}/did:example:alice/app.bsky.feed.post/3kbcq3p7ad422"
        ))
        .unwrap();
        let cid_a =
            Cid::parse("bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244").unwrap();
        let cid_b =
            Cid::parse("bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a").unwrap();
        let h = record_mac_headers(&uri, &cid_a, &req, &host_secret);
        assert_eq!(h.covered_value, format!("uri=\"{uri}\", cid=\"{cid_a}\""));
        verify_record_mac(&uri, &cid_a, &enc, &fields(&h)).unwrap();
        assert_eq!(
            verify_record_mac(&uri, &cid_b, &enc, &fields(&h)),
            Err(SignatureError::CoveredMismatch)
        );
        let other = SpaceRecordUri::parse(&format!(
            "{SPACE}/did:example:alice/app.bsky.feed.post/3kbcq3p7ad423"
        ))
        .unwrap();
        assert_eq!(
            verify_record_mac(&other, &cid_a, &enc, &fields(&h)),
            Err(SignatureError::CoveredMismatch)
        );
        // A record MAC is never accepted as a commit MAC.
        assert_eq!(
            verify_commit_mac(&commit(), &enc, &fields(&h)),
            Err(SignatureError::MissingTagged)
        );
    }
}
