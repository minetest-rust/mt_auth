use mt_net::{CltSender, SenderExt, ToCltPkt, ToSrvPkt};
use rand::RngCore;
use sha2::Sha256;
use srp::{client::SrpClient, groups::G_2048};
use std::time::Duration;
use tokio::time::{interval, Interval};

enum AuthState {
    Init(ToSrvPkt, Interval),
    Verify(Vec<u8>, SrpClient<'static, Sha256>),
    Done(bool),
}

pub struct Auth {
    tx: CltSender,
    state: AuthState,
    username: String,
    password: String,
    lang: String,
}

impl Auth {
    pub fn new(
        tx: CltSender,
        username: impl Into<String>,
        password: impl Into<String>,
        lang: impl Into<String>,
    ) -> Self {
        let username = username.into();
        Self {
            tx,
            state: AuthState::Init(
                ToSrvPkt::Init {
                    serialize_version: 29,
                    proto_version: 40..=40,
                    player_name: username.clone(),
                    send_full_item_meta: false,
                },
                interval(Duration::from_millis(100)),
            ),
            username,
            password: password.into(),
            lang: lang.into(),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn lang(&self) -> &str {
        &self.lang
    }

    pub fn mut_init_pkt(&mut self) -> Option<&mut ToSrvPkt> {
        if let AuthState::Init(pkt, _) = &mut self.state {
            Some(pkt)
        } else {
            None
        }
    }

    pub async fn poll(&mut self) {
        match &mut self.state {
            AuthState::Init(pkt, interval) => {
                loop {
                    // cancel safety: since init pkt is unreliable, cancelation is not an issue
                    self.tx.send(pkt).await.unwrap();
                    interval.tick().await;
                }
            }
            AuthState::Verify(_, _) | AuthState::Done(false) => futures::future::pending().await,
            AuthState::Done(unconsumed) => {
                *unconsumed = false;
            }
        }
    }

    pub async fn handle_pkt(&mut self, pkt: &ToCltPkt) {
        use ToCltPkt::*;
        match pkt {
            Hello {
                auth_methods,
                username: name,
                ..
            } => {
                use mt_net::AuthMethod;

                if !matches!(self.state, AuthState::Init(_, _)) {
                    return;
                }

                let srp = SrpClient::<Sha256>::new(&G_2048);

                let mut rand_bytes = vec![0; 32];
                rand::thread_rng().fill_bytes(&mut rand_bytes);

                if &self.username != name {
                    panic!("username changed");
                }

                if auth_methods.contains(AuthMethod::FirstSrp) {
                    let verifier = srp.compute_verifier(
                        self.username.to_lowercase().as_bytes(),
                        self.password.as_bytes(),
                        &rand_bytes,
                    );

                    self.tx
                        .send(&ToSrvPkt::FirstSrp {
                            salt: rand_bytes,
                            verifier,
                            empty_passwd: self.password.is_empty(),
                        })
                        .await
                        .unwrap();

                    self.state = AuthState::Done(false);
                } else if auth_methods.contains(AuthMethod::Srp) {
                    let a = srp.compute_public_ephemeral(&rand_bytes);

                    self.tx
                        .send(&ToSrvPkt::SrpBytesA { a, no_sha1: true })
                        .await
                        .unwrap();

                    self.state = AuthState::Verify(rand_bytes, srp);
                } else {
                    panic!("unsupported auth methods: {auth_methods:?}");
                }
            }
            SrpBytesSaltB { salt, b } => {
                if let AuthState::Verify(a, srp) = &self.state {
                    let m = srp
                        .process_reply(
                            a,
                            self.username.to_lowercase().as_bytes(),
                            self.password.as_bytes(),
                            salt,
                            b,
                        )
                        .unwrap()
                        .proof()
                        .into();

                    self.tx.send(&ToSrvPkt::SrpBytesM { m }).await.unwrap();

                    self.state = AuthState::Done(false);
                }
            }
            AcceptAuth { .. } => {
                self.tx
                    .send(&ToSrvPkt::Init2 {
                        lang: self.lang.clone(),
                    })
                    .await
                    .unwrap();

                self.state = AuthState::Done(true);
            }
            _ => {}
        }
    }
}
