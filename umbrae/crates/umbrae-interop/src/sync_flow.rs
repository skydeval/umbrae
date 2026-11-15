//! `umbrae-sync` end to end against the reference PDS, as an app would run
//! it: authorize with a notification registration (confirmed over TLS),
//! sync a group in full, persist the cursor and credential, get a real
//! `notifySpaceUpdate` when a member posts, sync incrementally from the
//! restored cursor, and see a removed member leave the writer set.

use crate::umbrae_flow::delegation;
use crate::{Account, Pds, Report};
use serde_json::{json, Value};
use std::future::Future;
use std::io::Read;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use umbrae::space::{group_policy, group_space};
use umbrae::SPACE_TYPE;
use umbrae_core::drisl::Value as D;
use umbrae_lexicons::{Record, GROUP, GROUP_RKEY, POST};
use umbrae_sync::notify::{self, Notification, Update};
use umbrae_sync::{
    authorize, sync_space, Authorize, Checked, Credential, Identity, Method, Notify, RepoChange,
    Request, ResolveError, Response, SpaceCursor, Transport, TransportError,
};

const SKEY: &str = "3mbbbbbbbbbb5";
const CREATED: &str = "2026-11-14T10:00:00.000Z";
const NOTIFY_BIND: &str = "0.0.0.0:2583";
/// Served by the TLS front end, which proxies `/xrpc/` to [`NOTIFY_BIND`].
const NOTIFY_ENDPOINT: &str = "https://client.interop.test";

/// Run a future whose I/O is all blocking, so it's ready on first poll.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

pub(crate) struct Blocking<'a>(pub &'a ureq::Agent);

impl Transport for Blocking<'_> {
    async fn send(&self, req: Request) -> Result<Response, TransportError> {
        let url = req.url();
        let mut r = match req.method {
            Method::Get => self.0.get(&url),
            Method::Post => self.0.post(&url),
        };
        for (k, v) in &req.query {
            r = r.query(k, v);
        }
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        let res = match &req.body {
            Some(b) => r.send_json(b.clone()),
            None => r.call(),
        };
        let res = match res {
            Ok(r) | Err(ureq::Error::Status(_, r)) => r,
            Err(_) => return Err(TransportError::Unreachable),
        };
        let status = res.status();
        let headers = res
            .headers_names()
            .into_iter()
            .filter_map(|n| res.header(&n).map(|v| (n.clone(), v.to_owned())))
            .collect();
        let mut body = Vec::new();
        res.into_reader()
            .take(32 * 1024 * 1024)
            .read_to_end(&mut body)
            .map_err(|_| TransportError::Other)?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// Every account lives on the one PDS; keys come from the mock PLC.
pub(crate) struct Plc<'a> {
    pub dir: &'a crate::plc::Directory,
    pub pds: &'a str,
}

impl umbrae_sync::Directory for Plc<'_> {
    async fn resolve(&self, did: &str, _refresh: bool) -> Result<Identity, ResolveError> {
        if self.dir.op(did).is_none() {
            return Err(ResolveError::NotFound);
        }
        Ok(Identity {
            pds: self.pds.to_owned(),
            signing_key: self.dir.key(did, "atproto"),
            kem_key: self.dir.key(did, "atproto_kem"),
            label_key: None,
        })
    }
}

#[derive(Default)]
struct Inbox {
    token: Option<String>,
    confirmed: usize,
    refused: usize,
    notifications: Vec<Notification>,
}

/// The notification endpoint: confirms registrations carrying our token,
/// and records notifications that do.
fn serve_notifications(inbox: Arc<Mutex<Inbox>>) {
    let server =
        tiny_http::Server::http(NOTIFY_BIND).unwrap_or_else(|e| panic!("bind {NOTIFY_BIND}: {e}"));
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = Vec::new();
            let _ = req.as_reader().take(64 * 1024).read_to_end(&mut body);
            let path = req.url().split('?').next().unwrap_or("").to_owned();
            let mut ib = inbox.lock().unwrap();
            let expected = ib.token.clone().unwrap_or_default();
            let (status, reply) = if path == format!("/xrpc/{}", notify::CONFIRM_NSID) {
                match notify::parse_confirmation(&body) {
                    Ok(c) if notify::token_matches(&expected, &c.token) => {
                        ib.confirmed += 1;
                        (200, c.reply())
                    }
                    _ => {
                        ib.refused += 1;
                        (400, json!({ "error": "InvalidToken" }))
                    }
                }
            } else if path == format!("/xrpc/{}", notify::NOTIFY_NSID) {
                match notify::parse_notification(&body) {
                    Ok(n) if notify::token_matches(&expected, &n.token) => {
                        ib.notifications.push(n);
                        (200, json!({}))
                    }
                    _ => {
                        ib.refused += 1;
                        (400, json!({ "error": "InvalidToken" }))
                    }
                }
            } else {
                (404, json!({ "error": "NotFound" }))
            };
            drop(ib);
            let header =
                tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
                    .unwrap();
            let _ = req.respond(
                tiny_http::Response::from_string(reply.to_string())
                    .with_status_code(status)
                    .with_header(header),
            );
        }
    });
}

fn wait_for(
    inbox: &Arc<Mutex<Inbox>>,
    mut found: impl FnMut(&Notification) -> bool,
) -> Option<Notification> {
    for _ in 0..60 {
        if let Some(n) = inbox
            .lock()
            .unwrap()
            .notifications
            .iter()
            .find(|n| found(n))
            .cloned()
        {
            return Some(n);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

fn kinds(records: &[umbrae_sync::SyncedRecord]) -> Vec<&'static str> {
    let mut k: Vec<_> = records
        .iter()
        .map(|r| match &r.checked {
            Checked::Hidden(Record::Post(_)) => "post",
            Checked::Hidden(Record::Group(_)) => "group",
            Checked::Hidden(Record::Like(_)) => "like",
            Checked::Other => "pds",
            Checked::Invalid(_) => "invalid",
            _ => "?",
        })
        .collect();
    k.sort();
    k
}

pub(crate) fn run(
    pds: &Pds,
    dir: &crate::plc::Directory,
    report: &mut Report,
    alice: &Account,
    bob: &Account,
) -> Result<(), String> {
    let inbox = Arc::new(Mutex::new(Inbox::default()));
    serve_notifications(inbox.clone());
    let transport = Blocking(&pds.agent);
    let directory = Plc { dir, pds: &pds.url };
    let now = crate::now;

    // A fresh group: Alice names it, adds Bob, posts; Bob replies.
    let space = group_space(&alice.did, SKEY).map_err(|e| e.to_string())?;
    let space_str = space.to_string();
    let mut policy = json!({ "$type": "com.atproto.memberspace.policy" });
    for (k, v) in group_policy(None).to_map() {
        if let D::Bool(b) = v {
            policy[k] = json!(b);
        }
    }
    pds.post(
        "com.atproto.space.createSpace",
        &json!({ "spaceType": SPACE_TYPE, "skey": SKEY, "policy": policy }),
        &alice.auth(),
    )?
    .ok("createSpace sync")?;
    let write = |who: &Account, collection: &str, rkey: &str, record: Value| {
        pds.post(
            "com.atproto.space.createRecord",
            &json!({ "space": space_str, "repo": who.did, "collection": collection, "rkey": rkey, "record": record }),
            &who.auth(),
        )?
        .ok("createRecord sync")
    };
    write(
        alice,
        GROUP,
        GROUP_RKEY,
        json!({ "$type": GROUP, "name": "sync test", "createdAt": CREATED }),
    )?;
    pds.post(
        "com.atproto.memberspace.putMembers",
        &json!({ "space": space_str, "members": [{ "did": bob.did, "read": true, "write": true }] }),
        &alice.auth(),
    )?
    .ok("putMembers sync")?;
    write(
        alice,
        POST,
        "3mbaaaaaaad22",
        json!({ "$type": POST, "text": "first", "createdAt": CREATED }),
    )?;
    write(
        bob,
        POST,
        "3mbaaaaaaad23",
        json!({ "$type": POST, "text": "hi", "createdAt": CREATED }),
    )?;

    // Authorize through Bob's delegation, registering our endpoint.
    let token = notify::new_token();
    inbox.lock().unwrap().token = Some(token.clone());
    let reg = Notify {
        endpoint: NOTIFY_ENDPOINT.into(),
        token: token.clone(),
    };
    let d = delegation(pds, &space_str, bob)?;
    let cred = block_on(authorize(
        &transport,
        &directory,
        &space,
        Authorize {
            delegation: &d,
            attestation: None,
            notify: Some(&reg),
        },
        now(),
    ));
    let confirmed = inbox.lock().unwrap().confirmed;
    report.check(
        "sync: authorize verifies the credential, and the PDS confirmed our endpoint over TLS",
        match &cred {
            Ok(c) if confirmed >= 1 && c.space() == &space => {
                Ok(format!("{confirmed} confirmation(s)"))
            }
            Ok(_) => Err(format!("{confirmed} confirmations")),
            Err(e) => Err(e.to_string()),
        },
    );
    let cred = cred.map_err(|e| e.to_string())?;

    // Full sync from nothing.
    let (cursor, changes) = block_on(sync_space(
        &transport,
        &directory,
        &cred,
        &SpaceCursor::default(),
        now(),
    ))
    .map_err(|e| e.to_string())?;
    let mut seen = Vec::new();
    for c in &changes {
        match c {
            RepoChange::Replaced { repo, records } if repo == &alice.did => {
                seen.push(format!("alice {:?}", kinds(records)))
            }
            RepoChange::Replaced { repo, records } if repo == &bob.did => {
                seen.push(format!("bob {:?}", kinds(records)))
            }
            other => seen.push(format!("{other:?}")),
        }
    }
    seen.sort();
    report.check(
        "sync: a full sync replaces both repos with checked records",
        if seen
            == [
                "alice [\"group\", \"pds\", \"pds\", \"post\"]".to_owned(),
                "bob [\"post\"]".to_owned(),
            ]
        {
            Ok(seen.join("; "))
        } else {
            Err(seen.join("; "))
        },
    );

    // Persist both, as an app would across a restart.
    let saved_cursor = serde_json::to_string(&cursor).map_err(|e| e.to_string())?;
    let saved_cred = serde_json::to_string(&cred).map_err(|e| e.to_string())?;
    let cursor: SpaceCursor = serde_json::from_str(&saved_cursor).map_err(|e| e.to_string())?;
    let cred: Credential = serde_json::from_str(&saved_cred).map_err(|e| e.to_string())?;
    report.check(
        "sync: cursor and credential survive serialization",
        Ok(format!(
            "{} repos, {} bytes of cursor",
            cursor.repos.len(),
            saved_cursor.len()
        )),
    );

    // Alice posts again: the PDS notifies us.
    write(
        alice,
        POST,
        "3mbaaaaaaad24",
        json!({ "$type": POST, "text": "second", "createdAt": CREATED }),
    )?;
    let note = wait_for(
        &inbox,
        |n| matches!(&n.update, Update::RepoWrite { repo, .. } if repo == &alice.did),
    );
    report.check(
        "sync: a notifySpaceUpdate repoWrite arrives for Alice's post, with our token",
        match &note {
            Some(n) if n.space == space => Ok("repoWrite".into()),
            other => Err(format!(
                "{} notification(s), refused {}; got {other:?}",
                inbox.lock().unwrap().notifications.len(),
                inbox.lock().unwrap().refused
            )),
        },
    );

    // Incremental sync from the restored cursor.
    let (cursor, changes) = block_on(sync_space(&transport, &directory, &cred, &cursor, now()))
        .map_err(|e| e.to_string())?;
    report.check(
        "sync: an incremental sync replays only Alice's new post from the op log",
        match changes.as_slice() {
            [RepoChange::Ops { repo, ops }] if repo == &alice.did && ops.len() == 1 => {
                match &ops[0].record {
                    Some(r)
                        if matches!(r.checked, Checked::Hidden(Record::Post(_)))
                            && ops[0].rkey == "3mbaaaaaaad24" =>
                    {
                        Ok("1 op, a checked post".into())
                    }
                    other => Err(format!("{other:?}")),
                }
            }
            other => Err(format!("{} change(s): {other:?}", other.len())),
        },
    );

    // Alice removes Bob: he leaves the writer set, and we're told.
    pds.post(
        "com.atproto.memberspace.removeMembers",
        &json!({ "space": space_str, "dids": [bob.did] }),
        &alice.auth(),
    )?
    .ok("removeMembers sync")?;
    let removed = wait_for(
        &inbox,
        |n| matches!(&n.update, Update::RepoRemoved { repo, .. } if repo == &bob.did),
    );
    let d = delegation(pds, &space_str, alice)?;
    let cred = block_on(authorize(
        &transport,
        &directory,
        &space,
        Authorize {
            delegation: &d,
            attestation: None,
            notify: Some(&reg),
        },
        now(),
    ))
    .map_err(|e| e.to_string())?;
    let (_, changes) = block_on(sync_space(&transport, &directory, &cred, &cursor, now()))
        .map_err(|e| e.to_string())?;
    let bob_removed = changes
        .iter()
        .any(|c| matches!(c, RepoChange::Removed { repo } if repo == &bob.did));
    report.check(
        "sync: after Bob's removal a repoRemoved arrives, and the next sync drops his repo",
        if removed.is_some() && bob_removed {
            Ok(format!("{} change(s)", changes.len()))
        } else {
            Err(format!(
                "notified {} dropped {bob_removed}: {changes:?}",
                removed.is_some()
            ))
        },
    );
    report.check(
        "sync: nothing reached our endpoint without our token",
        match inbox.lock().unwrap().refused {
            0 => Ok("0 refused".into()),
            n => Err(format!("{n} refused")),
        },
    );
    Ok(())
}
