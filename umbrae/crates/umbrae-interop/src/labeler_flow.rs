//! The private-labeler flow, end to end against the reference PDS.
//!
//! A labeler creates its space with Umbrae's labeler policy (apps limited
//! to one client), adds a reader account, and writes its profile, policies,
//! reasons and signed labels: applications, negations, an expired label
//! and a purge. The reader syncs as the allowed client, attested with the
//! key that client publishes. Then the refusals: no attestation, another
//! client's attestation, a non-member, and non-labeler writes.

use crate::umbrae_flow::{delegation, map, sync};
use crate::{expect_refusal, Account, Pds, Report};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use umbrae::labeler::{
    check_labeler_policy, current_labels, labeler_policy, labeler_space, reader_member, sign_label,
    verify_label,
};
use umbrae::LABELER_SPACE_TYPE;
use umbrae_core::didkey;
use umbrae_core::drisl::Value as D;
use umbrae_core::policy::Policy;
use umbrae_core::tokens::{self, Signer};
use umbrae_core::uri::SpaceRef;
use umbrae_lexicons::{
    validate_labeler_record, Label, LabelerRecord, LABEL, LABELER_POLICIES, LABELER_PROFILE,
    LABELER_REASONS, SELF_RKEY,
};

const CLIENT_HOST: &str = "https://client.interop.test";
const CREATED: &str = "2026-11-13T10:00:00.000Z";
const KID: &str = "interop-key-1";

/// A client the PDS can resolve: its metadata, with the public half of its
/// attestation key, written where the TLS server in front of it serves.
struct Client {
    id: String,
    signer: Signer,
}

impl Client {
    fn publish(dir: &str, name: &str) -> Result<Self, String> {
        let key = SigningKey::random(&mut OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x().ok_or("no x")?, point.y().ok_or("no y")?);
        let id = format!("{CLIENT_HOST}/{name}.json");
        let metadata = json!({
            "client_id": id,
            "client_name": format!("interop {name}"),
            "application_type": "web",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "redirect_uris": [format!("{CLIENT_HOST}/{name}/callback")],
            "scope": "atproto",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
            "dpop_bound_access_tokens": true,
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": KID,
                "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y),
            }] },
        });
        std::fs::write(format!("{dir}/{name}.json"), metadata.to_string())
            .map_err(|e| format!("writing client metadata: {e}"))?;
        Ok(Self {
            id,
            signer: Signer::P256(key),
        })
    }

    fn attest(&self, authority: &str) -> String {
        tokens::create_client_attestation(
            &self.id,
            authority,
            Some(KID),
            &self.signer,
            crate::now(),
        )
    }
}

fn label(src: &str, uri: &str, val: &str, cts: &str) -> Label {
    Label {
        ver: Some(1),
        src: src.into(),
        uri: uri.into(),
        cid: None,
        val: val.into(),
        neg: false,
        cts: cts.into(),
        exp: None,
        sig: None,
    }
}

fn label_json(l: &Label) -> Value {
    let mut v = json!({ "$type": LABEL, "ver": l.ver.unwrap_or(1), "src": l.src, "uri": l.uri,
        "val": l.val, "cts": l.cts });
    if l.neg {
        v["neg"] = json!(true);
    }
    if let Some(exp) = &l.exp {
        v["exp"] = json!(exp);
    }
    if let Some(sig) = &l.sig {
        v["sig"] = json!({ "$bytes": STANDARD_NO_PAD.encode(sig) });
    }
    v
}

fn refused_sync(
    pds: &Pds,
    space: &SpaceRef,
    via: &Account,
    attestation: Option<&str>,
) -> Result<crate::Resp, String> {
    let key = SigningKey::random(&mut OsRng);
    let token = delegation(pds, &space.to_string(), via)?;
    let mut body = json!({ "space": space.to_string(),
        "credentialKey": didkey::format_p256(&key.verifying_key().into()), "delegationToken": token });
    if let Some(a) = attestation {
        body["clientAttestation"] = json!(a);
    }
    pds.post("com.atproto.space.authorizeSpaceSync", &body, &vec![])
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    outsider: &Account,
) -> Result<(), String> {
    let client_dir = std::env::var("CLIENT_DIR").unwrap_or_else(|_| "/client".into());
    let reader_app = Client::publish(&client_dir, "reader-app")?;
    let other_app = Client::publish(&client_dir, "other-app")?;
    let labeler = crate::create_account(pds, "modlist")?;
    let reader = crate::create_account(pds, "syncer")?;
    report.check(
        "labeler: accounts and client metadata",
        Ok(format!(
            "{} / {} / {}",
            labeler.did, reader.did, reader_app.id
        )),
    );

    // The space, created with Umbrae's labeler policy, as the PDS stores it.
    let space = labeler_space(&labeler.did).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let wanted = labeler_policy(vec![reader_app.id.clone()]);
    let mut policy_json = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in wanted.to_map() {
        match v {
            D::Bool(b) => policy_json[k] = json!(b),
            D::Array(a) => {
                policy_json[k] = json!(a.iter().filter_map(D::as_text).collect::<Vec<_>>())
            }
            _ => {}
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": LABELER_SPACE_TYPE, "skey": SELF_RKEY, "policy": policy_json }),
        &labeler.auth(),
    )?
    .ok("createSpace labeler")?;
    let got = pds
        .get(
            "com.atproto.space.getSpace",
            &[("space", &space_str)],
            &labeler.auth(),
        )?
        .ok("getSpace labeler")?
        .json();
    let stored = map(&got["policy"]).and_then(|m| Policy::from_map(&m).map_err(|e| e.to_string()));
    report.check(
        "labeler: the PDS stores the labeler policy exactly, and it passes check_labeler_policy",
        match stored {
            Ok(p) if p == wanted && check_labeler_policy(&space, &p).is_ok() => {
                Ok(space_str.clone())
            }
            Ok(p) => Err(format!("{p:?}")),
            Err(e) => Err(e),
        },
    );
    let m = reader_member();
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str,
            "members": [{ "did": reader.did, "read": m.read, "write": m.write }] }),
        &labeler.auth(),
    )?
    .ok("putMembers labeler")?;

    // Profile, policies, reasons, and signed labels.
    let write = |who: &Account, collection: &str, rkey: &str, record: &Value| {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection,
                "rkey": rkey, "record": record }),
            &who.auth(),
        )
    };
    write(
        &labeler,
        LABELER_PROFILE,
        SELF_RKEY,
        &json!({ "$type": LABELER_PROFILE, "displayName": "Private mod",
            "description": "members only", "createdAt": CREATED }),
    )?
    .ok("profile")?;
    write(
        &labeler,
        LABELER_POLICIES,
        SELF_RKEY,
        &json!({ "$type": LABELER_POLICIES,
        "policies": { "labelValues": ["spam", "rude", "nudity", "porn", "sexual"],
            "labelValueDefinitions": [{ "identifier": "rude", "severity": "inform", "blurs": "none",
                "defaultSetting": "warn",
                "locales": [{ "lang": "en", "name": "Rude", "description": "Rude content" }] }] },
        "reasonTypes": ["com.atproto.moderation.defs#reasonSpam"],
        "subjectTypes": ["record"], "createdAt": CREATED }),
    )?
    .ok("policies")?;
    write(
        &labeler,
        LABELER_REASONS,
        SELF_RKEY,
        &json!({ "$type": LABELER_REASONS,
        "reasons": [{ "type": "com.atproto.moderation.defs#reasonSpam",
            "locales": [{ "lang": "en", "title": "Spam", "description": "Unwanted promotion" }] }],
        "createdAt": CREATED }),
    )?
    .ok("reasons")?;

    let label_key = Signer::K256(k256_key());
    let a = format!("at://{}/app.bsky.feed.post/3mbaaaaaaacce", outsider.did);
    let b = format!("at://{}", outsider.did);
    let mut plan: Vec<(&str, Label)> = Vec::new();
    let src = labeler.did.as_str();
    plan.push((
        "3mbaaaaaaacc2",
        label(src, &a, "spam", "2026-11-13T10:00:00.000Z"),
    ));
    let mut neg = label(src, &a, "spam", "2026-11-13T11:00:00.000Z");
    neg.neg = true;
    plan.push(("3mbaaaaaaacc3", neg));
    plan.push((
        "3mbaaaaaaacc4",
        label(src, &a, "spam", "2026-11-13T12:00:00.000Z"),
    ));
    plan.push((
        "3mbaaaaaaacc5",
        label(src, &b, "rude", "2026-11-13T10:00:00.000Z"),
    ));
    let mut expired = label(src, &b, "nudity", "2026-11-13T10:00:00.000Z");
    expired.exp = Some("2026-11-13T10:30:00.000Z".into());
    plan.push(("3mbaaaaaaacc6", expired));
    plan.push((
        "3mbaaaaaaacc7",
        label(src, &a, "porn", "2026-11-13T10:00:00.000Z"),
    ));
    plan.push((
        "3mbaaaaaaacca",
        label(src, &b, "sexual", "2026-11-13T10:00:00.000Z"),
    ));
    let mut neg2 = label(src, &b, "sexual", "2026-11-13T11:00:00.000Z");
    neg2.neg = true;
    plan.push(("3mbaaaaaaaccb", neg2));
    for (rkey, l) in &mut plan {
        l.sig = Some(sign_label(l, &label_key));
        write(&labeler, LABEL, rkey, &label_json(l))?.ok("label")?;
    }
    // A purge: the porn label is deleted outright.
    pds.post(
        "com.atproto.space.deleteRecord",
        &json!({ "space": space_str, "repo": labeler.did, "collection": LABEL,
            "rkey": "3mbaaaaaaacc7" }),
        &labeler.auth(),
    )?
    .ok("purge")?;

    // Others writing labels into their own repos for the space: a reader
    // (no write access) and an outsider forging the labeler as src.
    let forged = label(src, &a, "spam", "2026-11-13T13:00:00.000Z");
    let mut forged_neg = forged.clone();
    forged_neg.neg = true;
    let reader_write = write(&reader, LABEL, "3mbaaaaaaaccc", &label_json(&forged_neg))?;
    let outsider_write = write(outsider, LABEL, "3mbaaaaaaaccd", &label_json(&forged_neg))?;

    // The reader syncs as the allowed app.
    let attestation = reader_app.attest(&labeler.did);
    let synced = sync(pds, dir, &space, &reader, Some(&attestation))?;
    report.check(
        "labeler: the reader syncs through the allowed app's attestation; only the labeler is a writer",
        // Both PDS writes must have been accepted for the writer set to
        // prove they aren't tracked.
        if reader_write.status != 200 || outsider_write.status != 200 {
            Err(format!(
                "a write was refused (reader HTTP {}, outsider HTTP {}), so the writer set proves nothing",
                reader_write.status, outsider_write.status
            ))
        } else if synced.writers == [labeler.did.clone()] {
            Ok(format!(
                "reader write HTTP {}, outsider write HTTP {}",
                reader_write.status, outsider_write.status
            ))
        } else {
            Err(format!("{:?}", synced.writers))
        },
    );

    let empty = Vec::new();
    let records = synced.repos.get(&labeler.did).unwrap_or(&empty);
    let mut kinds = BTreeSet::new();
    let mut labels: Vec<(String, Label)> = Vec::new();
    let mut bad = Vec::new();
    for r in records {
        let uri = space
            .record(&labeler.did, &r.collection, &r.rkey)
            .map_err(|e| e.to_string())?;
        match validate_labeler_record(&uri, &r.value) {
            Ok(None) => {}
            Ok(Some(LabelerRecord::Label(l))) => {
                kinds.insert("label");
                labels.push((r.rkey.clone(), *l));
            }
            Ok(Some(LabelerRecord::Profile(_))) => {
                kinds.insert("profile");
            }
            Ok(Some(LabelerRecord::Policies(_))) => {
                kinds.insert("policies");
            }
            Ok(Some(LabelerRecord::Reasons(_))) => {
                kinds.insert("reasons");
            }
            Err(e) => bad.push(format!("{} {e}", r.rkey)),
        }
    }
    report.check(
        "labeler: every synced record validates (profile, policies, reasons, 7 labels after the purge)",
        if bad.is_empty() && kinds.len() == 4 && labels.len() == 7 {
            Ok(format!("{kinds:?}"))
        } else {
            Err(format!("{kinds:?} {} labels {bad:?}", labels.len()))
        },
    );
    let key = didkey::parse_any(&label_key.did_key()).map_err(|e| e.to_string())?;
    report.check(
        "labeler: every label's signature verifies after the round trip through the PDS",
        if labels.len() == 7 && labels.iter().all(|(_, l)| verify_label(l, &key)) {
            Ok(format!("{} signatures", labels.len()))
        } else {
            Err(format!("{} labels, or a signature failed", labels.len()))
        },
    );
    let now_ms = crate::now() * 1000;
    let current: Vec<_> = current_labels(labels.iter().map(|(k, l)| (k.as_str(), l)), now_ms)
        .into_iter()
        .map(|l| format!("{} {}", if l.uri == a { "post" } else { "account" }, l.val))
        .collect();
    report.check(
        "labeler: labels in effect are the re-applied spam and rude (negated, expired, purged gone)",
        if current == ["account rude", "post spam"] {
            Ok(current.join(", "))
        } else {
            Err(format!("{current:?}"))
        },
    );

    // Refusals.
    let r = refused_sync(pds, &space, &reader, None)?;
    report.check(
        "labeler: a member without a client attestation gets no credential",
        expect_refusal(&r, Some("AppNotAuthorized")),
    );
    let r = refused_sync(pds, &space, &reader, Some(&other_app.attest(&labeler.did)))?;
    report.check(
        "labeler: a member attested as another app gets no credential",
        expect_refusal(&r, Some("AppNotAuthorized")),
    );
    let r = refused_sync(
        pds,
        &space,
        outsider,
        Some(&reader_app.attest(&labeler.did)),
    )?;
    report.check(
        "labeler: a non-member gets no credential, even through the allowed app",
        expect_refusal(&r, Some("SpaceNotFound")),
    );
    let outsider_uri = space
        .record(&outsider.did, LABEL, "3mbaaaaaaaccd")
        .map_err(|e| e.to_string())?;
    let mut forged_value = map(&label_json(&forged_neg))?;
    forged_value.remove("sig");
    report.check(
        "labeler: a label from any repo but the labeler's is refused by validation",
        match validate_labeler_record(&outsider_uri, &forged_value) {
            Err(e) => Ok(e.to_string()),
            Ok(v) => Err(format!("{v:?}")),
        },
    );
    Ok(())
}

fn k256_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::random(&mut OsRng)
}
