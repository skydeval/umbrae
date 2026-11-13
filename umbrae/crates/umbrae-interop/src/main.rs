//! Interop harness: a syncer built on `umbrae-core`, run against the
//! reference spaces PDS (`ghcr.io/bluesky-social/atproto:pds-spaces-alpha`).
//!
//! It serves a mock PLC directory for the PDS, creates accounts, sets up a
//! memberspace with a member who writes, and then syncs that member's repo
//! the way a real syncer would: delegation token, space credential bound
//! to our own key, credential-use signatures, KEM key shares and MACs, the
//! commit, the STAR archive and the operation log. Every check runs our
//! code against the reference implementation's, in both directions.
//!
//! Run by `scripts/interop.sh` on the build machine; never against a public
//! service.

mod lexjson;
mod plc;

use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use umbrae_core::cid::Cid;
use umbrae_core::commit::RepoOp;
use umbrae_core::httpsig;
use umbrae_core::kem::{self, Encapsulation};
use umbrae_core::mac::{self, MacFields, MacProfile};
use umbrae_core::repo_archive::read_repo_archive;
use umbrae_core::tokens::{self, Expect, TokenKind};
use umbrae_core::uri::{SpaceRecordUri, SpaceRef};
use umbrae_core::{didkey, drisl, LtHash};

const SPACE_TYPE: &str = "com.example.interop";
const SKEY: &str = "interop";
const COLLECTION: &str = "com.example.post";

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn error_name(&self) -> String {
        self.json()
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    }

    fn ok(self, what: &str) -> Result<Self, String> {
        if self.status == 200 {
            Ok(self)
        } else {
            Err(format!(
                "{what}: HTTP {} {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            ))
        }
    }

    fn mac_fields(&self, profile: MacProfile) -> MacFields<'_> {
        MacFields {
            covered: self.header(profile.header()),
            signature_input: self.header("signature-input"),
            signature: self.header("signature"),
        }
    }
}

type Headers = Vec<(&'static str, String)>;

fn finish(r: Result<ureq::Response, ureq::Error>) -> Result<Resp, String> {
    let resp = match r {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    let headers = resp
        .headers_names()
        .into_iter()
        .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_owned())))
        .collect();
    let mut body = Vec::new();
    resp.into_reader()
        .take(32 * 1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    Ok(Resp {
        status,
        headers,
        body,
    })
}

struct Pds {
    url: String,
    agent: ureq::Agent,
}

impl Pds {
    fn get(&self, nsid: &str, params: &[(&str, &str)], headers: &Headers) -> Result<Resp, String> {
        let mut r = self.agent.get(&format!("{}/xrpc/{nsid}", self.url));
        for (k, v) in params {
            r = r.query(k, v);
        }
        for (k, v) in headers {
            r = r.set(k, v);
        }
        finish(r.call())
    }

    fn post(&self, nsid: &str, body: &Value, headers: &Headers) -> Result<Resp, String> {
        let mut r = self.agent.post(&format!("{}/xrpc/{nsid}", self.url));
        for (k, v) in headers {
            r = r.set(k, v);
        }
        finish(r.send_json(body.clone()))
    }
}

struct Account {
    did: String,
    access: String,
}

impl Account {
    fn auth(&self) -> Headers {
        vec![("Authorization", format!("Bearer {}", self.access))]
    }
}

#[derive(Default)]
struct Report {
    rows: Vec<(String, Result<String, String>)>,
}

impl Report {
    fn check(&mut self, name: &str, r: Result<String, String>) {
        let mark = if r.is_ok() { "PASS" } else { "FAIL" };
        let detail = match &r {
            Ok(d) | Err(d) => d.clone(),
        };
        println!("[{mark}] {name}: {detail}");
        self.rows.push((name.to_owned(), r));
    }

    fn failed(&self) -> usize {
        self.rows.iter().filter(|(_, r)| r.is_err()).count()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The headers of a request presenting a space credential to `audience`.
fn credential_headers(credential: &str, audience: &str, key: &SigningKey) -> Headers {
    let authorization = format!("Atproto-Space-Credential {credential}");
    let s = httpsig::sign_credential_use(&authorization, audience, key);
    vec![
        ("Authorization", authorization),
        ("Atproto-Space-Audience", audience.to_owned()),
        ("Signature-Input", s.signature_input),
        ("Signature", s.signature),
    ]
}

fn with_mac(mut h: Headers, profile: MacProfile, enc: &Encapsulation) -> Headers {
    h.push((
        "Accept-Signature",
        mac::format_mac_request(profile, &enc.key_share),
    ));
    h
}

fn wait_ready(pds: &Pds) -> Result<(), String> {
    for _ in 0..180 {
        if let Ok(r) = pds.get("com.atproto.server.describeServer", &[], &vec![]) {
            if r.status == 200 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err("PDS did not become ready in 180 s".into())
}

fn create_account(pds: &Pds, name: &str) -> Result<Account, String> {
    let r = pds
        .post(
            "com.atproto.server.createAccount",
            &json!({
                "handle": format!("{name}.test"),
                "email": format!("{name}@example.com"),
                "password": format!("{name}-interop-password"),
            }),
            &vec![],
        )?
        .ok("createAccount")?;
    let j = r.json();
    let did = j["did"].as_str().unwrap_or_default().to_owned();
    let access = j["accessJwt"].as_str().unwrap_or_default().to_owned();
    if !did.starts_with("did:plc:") || access.len() < 20 {
        return Err(format!("bad createAccount response for {name}: {j}"));
    }
    Ok(Account { did, access })
}

fn main() {
    let url = std::env::var("PDS_URL").unwrap_or_else(|_| "http://umbrae-interop-pds:3000".into());
    let bind = std::env::var("PLC_BIND").unwrap_or_else(|_| "0.0.0.0:2582".into());
    let dir = plc::Directory::default();
    dir.serve(&bind);
    let pds = Pds {
        url,
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build(),
    };
    let mut report = Report::default();
    let result = run(&pds, &dir, &mut report);
    println!();
    let failed = report.failed();
    match result {
        Err(e) => {
            println!(
                "ABORTED after {} checks ({failed} failed): {e}",
                report.rows.len()
            );
            std::process::exit(1);
        }
        Ok(()) if failed > 0 => {
            println!("{failed} of {} checks FAILED", report.rows.len());
            std::process::exit(1);
        }
        Ok(()) => println!("all {} checks passed", report.rows.len()),
    }
}

fn run(pds: &Pds, dir: &plc::Directory, report: &mut Report) -> Result<(), String> {
    wait_ready(pds)?;
    report.check("PDS ready", Ok(pds.url.clone()));

    // Accounts. Echo each DID and token length, so a null credential is
    // caught here rather than several steps on.
    let alice = create_account(pds, "alice")?;
    let bob = create_account(pds, "bob")?;
    let carol = create_account(pds, "carol")?;
    for (n, a) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        report.check(
            &format!("createAccount {n}"),
            Ok(format!("{} accessJwt len {}", a.did, a.access.len())),
        );
    }

    // Keys from the (mock) PLC directory, as a syncer resolves them.
    let kem_of = |did: &str| -> Result<String, String> {
        let k = dir
            .key(did, "atproto_kem")
            .ok_or_else(|| format!("no #atproto_kem for {did}"))?;
        didkey::parse_p256(&k).map_err(|e| format!("{did} #atproto_kem: {e}"))?;
        Ok(k)
    };
    let signing_of = |did: &str| -> Option<String> { dir.key(did, "atproto") };
    let bob_kem = kem_of(&bob.did)?;
    report.check(
        "genesis op publishes a P-256 #atproto_kem",
        Ok(format!("bob {bob_kem}")),
    );

    // Alice's memberspace, with Bob as a reading, writing member.
    let r = pds
        .post(
            "com.atproto.space.createSpace",
            &json!({
                "spaceType": SPACE_TYPE,
                "skey": SKEY,
                "policy": { "$type": "com.atproto.memberspace.policy", "publicRead": false },
            }),
            &alice.auth(),
        )?
        .ok("createSpace")?;
    let space_str = r.json()["space"].as_str().unwrap_or_default().to_owned();
    let space = SpaceRef::parse(&space_str).map_err(|e| format!("space {space_str}: {e}"))?;
    let expected = SpaceRef::new(&alice.did, SPACE_TYPE, SKEY).unwrap();
    report.check(
        "space ref matches our formatting",
        if space == expected && space.to_string() == space_str {
            Ok(space_str.clone())
        } else {
            Err(format!("{space_str} vs {expected}"))
        },
    );
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str, "members": [{ "did": bob.did, "read": true, "write": true }] }),
        &alice.auth(),
    )?
    .ok("putMembers")?;

    // Bob writes: three creates, an update and a delete.
    let mut cid_rows = Vec::new();
    let write = |nsid: &str, rkey: &str, text: Option<&str>| -> Result<Resp, String> {
        let mut body =
            json!({ "space": space_str, "repo": bob.did, "collection": COLLECTION, "rkey": rkey });
        if let Some(t) = text {
            body["record"] = json!({ "$type": COLLECTION, "text": t });
        }
        pds.post(nsid, &body, &bob.auth())?.ok(nsid)
    };
    for (nsid, rkey, text) in [
        (
            "com.atproto.space.createRecord",
            "3mbaaaaaaaaa2",
            Some("hello"),
        ),
        (
            "com.atproto.space.createRecord",
            "3mbaaaaaaaaa3",
            Some("world"),
        ),
        (
            "com.atproto.space.createRecord",
            "3mbaaaaaaaaa4",
            Some("going away"),
        ),
        (
            "com.atproto.space.putRecord",
            "3mbaaaaaaaaa2",
            Some("hello again"),
        ),
    ] {
        let r = write(nsid, rkey, text)?;
        let theirs = r.json()["cid"].as_str().unwrap_or_default().to_owned();
        let ours = drisl::encode(&lexjson::to_drisl(
            &json!({ "$type": COLLECTION, "text": text }),
        )?)
        .map(|b| Cid::for_drisl(&b).to_string())
        .map_err(|e| e.to_string())?;
        cid_rows.push((rkey.to_owned(), theirs == ours, theirs, ours));
    }
    write("com.atproto.space.deleteRecord", "3mbaaaaaaaaa4", None)?;
    report.check(
        "record CIDs: our DRISL encoding matches the PDS",
        if cid_rows.iter().all(|r| r.1) {
            Ok(format!("{} writes", cid_rows.len()))
        } else {
            Err(format!("{cid_rows:?}"))
        },
    );

    // Delegation token, minted by Bob's PDS, verified with our code.
    let delegation = pds
        .get(
            "com.atproto.space.getDelegationToken",
            &[("space", &space_str)],
            &bob.auth(),
        )?
        .ok("getDelegationToken")?
        .json()["token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let host_aud = tokens::space_host_aud(&alice.did);
    report.check(
        "delegation token verifies with umbrae-core",
        tokens::verify(
            TokenKind::Delegation,
            &delegation,
            now(),
            &Expect {
                aud: Some(&host_aud),
                sub: Some(&space_str),
            },
            |iss, _| signing_of(iss),
        )
        .map(|c| {
            format!(
                "iss {} alg {}",
                c.iss,
                tokens::parse(TokenKind::Delegation, &delegation)
                    .unwrap()
                    .header
                    .alg
            )
        })
        .map_err(|e| e.to_string()),
    );

    // A space credential bound to our own key.
    let cred_key = SigningKey::random(&mut OsRng);
    let cred_kid = didkey::format_p256(&cred_key.verifying_key().into());
    let r = pds
        .post(
            "com.atproto.space.authorizeSpaceSync",
            &json!({ "space": space_str, "credentialKey": cred_kid, "delegationToken": delegation }),
            &vec![],
        )?
        .ok("authorizeSpaceSync")?;
    let credential = r.json()["credential"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    report.check(
        "space credential verifies with umbrae-core, bound to our key",
        tokens::verify(
            TokenKind::Credential,
            &credential,
            now(),
            &Expect {
                aud: None,
                sub: Some(&space_str),
            },
            |iss, _| signing_of(iss),
        )
        .map_err(|e| e.to_string())
        .and_then(|c| {
            if c.cnf_kid.as_deref() == Some(cred_kid.as_str()) && c.iss == alice.did {
                Ok(format!("ttl {} s", c.exp - c.iat.unwrap_or(c.exp)))
            } else {
                Err(format!("cnf {:?} iss {}", c.cnf_kid, c.iss))
            }
        }),
    );

    // The delegation token is single use.
    let reuse = pds.post(
        "com.atproto.space.authorizeSpaceSync",
        &json!({ "space": space_str, "credentialKey": cred_kid, "delegationToken": delegation }),
        &vec![],
    )?;
    report.check(
        "a delegation token is refused the second time",
        if reuse.status != 200 {
            Ok(format!("HTTP {} {}", reuse.status, reuse.error_name()))
        } else {
            Err("accepted twice".into())
        },
    );

    // The writer set, through our credential-use signature.
    let r = pds
        .get(
            "com.atproto.space.listWriters",
            &[("space", &space_str)],
            &credential_headers(&credential, &alice.did, &cred_key),
        )?
        .ok("listWriters")?;
    let writers = r.json();
    let bob_entry = writers["repos"]
        .as_array()
        .and_then(|a| a.iter().find(|w| w["repo"] == json!(bob.did)))
        .cloned();
    let writer_data = bob_entry
        .as_ref()
        .and_then(|w| lexjson::bytes(&w["data"]))
        .unwrap_or_default();
    report.check(
        "listWriters accepts our credential signature and lists Bob",
        if writer_data.len() == 32 {
            Ok(format!("repoRev {}", bob_entry.unwrap()["repoRev"]))
        } else {
            Err(format!("{writers}"))
        },
    );

    let bob_cred = || credential_headers(&credential, &bob.did, &cred_key);
    let fresh_share = || kem::encapsulate(&bob_kem).map_err(|e| e.to_string());

    // getLatestCommit, MAC'd under a fresh key share.
    let enc = fresh_share()?;
    let r = pds
        .get(
            "com.atproto.space.getLatestCommit",
            &[("space", &space_str), ("repo", &bob.did)],
            &with_mac(bob_cred(), MacProfile::Commit, &enc),
        )?
        .ok("getLatestCommit")?;
    let latest = lexjson::commit(&r.json()["commit"])?;
    report.check(
        "getLatestCommit: PDS decapsulates our key share, MAC verifies",
        mac::verify_commit_mac(&latest, &enc, &r.mac_fields(MacProfile::Commit))
            .map_err(|e| e.to_string())
            .and_then(|_| {
                latest
                    .check_for(&bob.did, &space)
                    .map_err(|e| e.to_string())
            })
            .map(|_| format!("rev {}", latest.rev())),
    );
    report.check(
        "commit data agrees with listWriters",
        if latest.data()[..] == writer_data[..] {
            Ok("32 bytes".into())
        } else {
            Err("differs".into())
        },
    );

    // getRepo: the STAR archive, verified as it streams.
    let enc = fresh_share()?;
    let r = pds
        .get(
            "com.atproto.space.getRepo",
            &[("space", &space_str), ("repo", &bob.did)],
            &with_mac(bob_cred(), MacProfile::Commit, &enc),
        )?
        .ok("getRepo")?;
    let archive = read_repo_archive(&r.body);
    report.check(
        "getRepo: STAR parses, records hash to the commit (LtHash agrees)",
        match &archive {
            Ok((c, recs)) => {
                let names: Vec<_> = recs.iter().map(|r| r.rkey.as_str()).collect();
                if recs.len() == 2 && c == &latest {
                    Ok(format!("{} records {names:?}", recs.len()))
                } else {
                    Err(format!("{} records {names:?}, commit {c:?}", recs.len()))
                }
            }
            Err(e) => Err(format!(
                "{e} ({} bytes, content-type {:?})",
                r.body.len(),
                r.header("content-type")
            )),
        },
    );
    if let Ok((c, _)) = &archive {
        report.check(
            "getRepo: commit MAC verifies",
            mac::verify_commit_mac(c, &enc, &r.mac_fields(MacProfile::Commit))
                .map(|_| "ok".into())
                .map_err(|e| e.to_string()),
        );
    }

    // listRepoOps: replay the log into our own set hash.
    let enc = fresh_share()?;
    let r = pds
        .get(
            "com.atproto.space.listRepoOps",
            &[("space", &space_str), ("repo", &bob.did)],
            &with_mac(bob_cred(), MacProfile::Commit, &enc),
        )?
        .ok("listRepoOps")?;
    let j = r.json();
    let ops_commit = lexjson::commit(&j["commit"])?;
    report.check(
        "listRepoOps: commit MAC verifies",
        mac::verify_commit_mac(&ops_commit, &enc, &r.mac_fields(MacProfile::Commit))
            .map(|_| "ok".into())
            .map_err(|e| e.to_string()),
    );
    let mut hash = LtHash::new();
    let mut value_mismatches = Vec::new();
    let empty = Vec::new();
    let ops = j["ops"].as_array().unwrap_or(&empty);
    for op in ops {
        let cid = op["cid"]
            .as_str()
            .map(Cid::parse)
            .transpose()
            .map_err(|e| e.to_string())?;
        let prev = op["prev"]
            .as_str()
            .map(Cid::parse)
            .transpose()
            .map_err(|e| e.to_string())?;
        hash.apply_op(&RepoOp {
            collection: op["collection"].as_str().unwrap_or_default().to_owned(),
            rkey: op["rkey"].as_str().unwrap_or_default().to_owned(),
            cid,
            prev,
        })
        .map_err(|e| e.to_string())?;
        if let (Some(v), Some(c)) = (op.get("value").filter(|v| !v.is_null()), cid) {
            let ours = drisl::encode(&lexjson::to_drisl(v)?).map(|b| Cid::for_drisl(&b));
            if ours.as_ref().ok() != Some(&c) {
                value_mismatches.push(format!("{} {c}", op["rkey"]));
            }
        }
    }
    report.check(
        "listRepoOps: replaying the log reproduces the commit digest",
        if ops_commit.matches(&hash) && ops_commit == latest {
            Ok(format!("{} ops", ops.len()))
        } else {
            Err(format!("{} ops, digest mismatch", ops.len()))
        },
    );
    report.check(
        "listRepoOps: inline values hash to their CIDs",
        if value_mismatches.is_empty() {
            Ok("ok".into())
        } else {
            Err(value_mismatches.join(", "))
        },
    );

    // getRecord with a record MAC.
    let enc = fresh_share()?;
    let r = pds
        .get(
            "com.atproto.space.getRecord",
            &[
                ("space", &space_str),
                ("repo", &bob.did),
                ("collection", COLLECTION),
                ("rkey", "3mbaaaaaaaaa2"),
            ],
            &with_mac(bob_cred(), MacProfile::Record, &enc),
        )?
        .ok("getRecord")?;
    let j = r.json();
    let uri = space
        .record(&bob.did, COLLECTION, "3mbaaaaaaaaa2")
        .map_err(|e| e.to_string())?;
    let value_cid = drisl::encode(&lexjson::to_drisl(&j["value"])?)
        .map(|b| Cid::for_drisl(&b))
        .map_err(|e| e.to_string())?;
    report.check(
        "getRecord: record MAC verifies over uri and our computed CID",
        if j["uri"] != json!(uri.to_string()) || j["cid"] != json!(value_cid.to_string()) {
            Err(format!(
                "uri {} cid {} vs ours {value_cid}",
                j["uri"], j["cid"]
            ))
        } else {
            mac::verify_record_mac(&uri, &value_cid, &enc, &r.mac_fields(MacProfile::Record))
                .map(|_| format!("{}", j["value"]["text"]))
                .map_err(|e| e.to_string())
        },
    );
    let _ = SpaceRecordUri::parse(&uri.to_string()).map_err(|e| e.to_string())?;

    // Refusals.
    let r = pds.get(
        "com.atproto.space.getLatestCommit",
        &[("space", &space_str), ("repo", &bob.did)],
        &bob_cred(),
    )?;
    report.check(
        "a credential read without Accept-Signature is refused",
        expect_refusal(&r, Some("InvalidSpaceMac")),
    );
    let wrong_key = SigningKey::random(&mut OsRng);
    let r = pds.get(
        "com.atproto.space.getLatestCommit",
        &[("space", &space_str), ("repo", &bob.did)],
        &with_mac(
            credential_headers(&credential, &bob.did, &wrong_key),
            MacProfile::Commit,
            &fresh_share()?,
        ),
    )?;
    report.check(
        "a credential signed by another key is refused",
        expect_refusal(&r, None),
    );
    let r = pds.get(
        "com.atproto.space.getLatestCommit",
        &[("space", &space_str), ("repo", &bob.did)],
        &with_mac(
            credential_headers(&credential, &alice.did, &cred_key),
            MacProfile::Commit,
            &fresh_share()?,
        ),
    )?;
    report.check(
        "a credential addressed to another audience is refused",
        expect_refusal(&r, None),
    );
    let other = fresh_share()?;
    let enc = fresh_share()?;
    let r = pds
        .get(
            "com.atproto.space.getLatestCommit",
            &[("space", &space_str), ("repo", &bob.did)],
            &with_mac(bob_cred(), MacProfile::Commit, &enc),
        )?
        .ok("getLatestCommit")?;
    report.check(
        "our MAC check refuses a response under another key share",
        match mac::verify_commit_mac(&latest, &other, &r.mac_fields(MacProfile::Commit)) {
            Err(e) => Ok(e.to_string()),
            Ok(()) => Err("accepted".into()),
        },
    );

    // A non-member gets no credential, and is told the space doesn't exist.
    let carol_delegation = pds
        .get(
            "com.atproto.space.getDelegationToken",
            &[("space", &space_str)],
            &carol.auth(),
        )?
        .ok("getDelegationToken carol")?
        .json()["token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let r = pds.post(
        "com.atproto.space.authorizeSpaceSync",
        &json!({ "space": space_str, "credentialKey": cred_kid, "delegationToken": carol_delegation }),
        &vec![],
    )?;
    report.check(
        "a non-member is refused a credential as SpaceNotFound",
        expect_refusal(&r, Some("SpaceNotFound")),
    );

    // An account reads its own repo with its own session, no MAC needed.
    let r = pds.get(
        "com.atproto.space.getLatestCommit",
        &[("space", &space_str), ("repo", &bob.did)],
        &bob.auth(),
    )?;
    report.check(
        "an account reads its own repo without a MAC",
        if r.status == 200 {
            Ok("ok".into())
        } else {
            Err(format!("HTTP {} {}", r.status, r.error_name()))
        },
    );
    Ok(())
}

fn expect_refusal(r: &Resp, name: Option<&str>) -> Result<String, String> {
    let got = r.error_name();
    match (r.status, name) {
        (200, _) => Err("accepted".into()),
        (_, Some(n)) if got != n => Err(format!("HTTP {} {got}, wanted {n}", r.status)),
        (s, _) => Ok(format!("HTTP {s} {got}")),
    }
}
