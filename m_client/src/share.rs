use std::time::Duration;

use anyhow::{Context, Result};
use rand::RngExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use m_core::crypto::{CryptoKey, AsymmetricCipher, Hash, Kem, Signature, SymmetricEncryption};
use m_core::crypto::algorithms::hash::Blake3Hash;
use m_core::crypto::algorithms::kem::Kyber512;
use m_core::crypto::algorithms::signature::Dilithium2;
use m_core::crypto::algorithms::symmetric::Aes256Gcm;
use m_core::crypto::key::Key;

use crate::sharing::{
    InviteMsg, KemOffer, SharePacket, ShareData,
    encode_frame, decode_frame,
};
use crate::live::LiveEvent;
use crate::store::{Store, IdentityRecord, ContactRecord};

const TOR_CONTROL: &str = "127.0.0.1:9051";
const TOR_SOCKS: &str = "127.0.0.1:9050";
const TOR_CONTROL_PORT: u16 = 9051;
const TOR_SOCKS_PORT: u16 = 9050;
const TOR_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);

fn parse_bootstrap_pct(line: &str) -> Option<u8> {
    let idx = line.find("Bootstrapped ")?;
    let rest = &line[idx + "Bootstrapped ".len()..];
    let end = rest.find('%')?;
    rest[..end].trim().parse().ok()
}

pub async fn spawn_tor(
    event_tx: &mpsc::UnboundedSender<LiveEvent>,
) -> Result<Option<tokio::process::Child>> {
    if tokio::net::TcpStream::connect(TOR_CONTROL).await.is_ok() {
        return Ok(None);
    }

    let data_dir = std::env::temp_dir().join(format!("m_tor_{TOR_CONTROL_PORT}"));
    std::fs::create_dir_all(&data_dir)?;

    let torrc_content = format!(
        "DataDirectory {}\nControlPort {TOR_CONTROL_PORT}\nSocksPort {TOR_SOCKS_PORT}\nCookieAuthentication 1\nMaxCircuitDirtiness 600\n",
        data_dir.display(),
    );
    let torrc_path = data_dir.join("torrc");
    std::fs::write(&torrc_path, torrc_content)?;

    let mut child = tokio::process::Command::new("tor")
        .arg("-f")
        .arg(&torrc_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn tor (is it installed?)")?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let deadline = tokio::time::sleep(TOR_BOOTSTRAP_TIMEOUT);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                let _ = child.kill().await;
                anyhow::bail!("tor bootstrap timeout ({}s)", TOR_BOOTSTRAP_TIMEOUT.as_secs());
            }
            line = lines.next_line() => {
                match line? {
                    None => anyhow::bail!("tor exited before bootstrap completed"),
                    Some(l) => {
                        if let Some(pct) = parse_bootstrap_pct(&l) {
                            let _ = event_tx.send(LiveEvent::TorBootstrap(pct));
                            if pct >= 100 { break; }
                        }
                    }
                }
            }
        }
    }

    Ok(Some(child))
}

fn derive_aes_key(shared_secret: &[u8]) -> Result<Aes256Gcm> {
    let key_bytes = Blake3Hash::hash(shared_secret, 32)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    let key: Key<32> = CryptoKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("bad derived key: {e}"))?;
    Ok(Aes256Gcm::from_key(key))
}

fn build_signer(identity: &IdentityRecord) -> Result<Dilithium2> {
    let sk = CryptoKey::from_bytes(&identity.signing_sk_bytes)
        .map_err(|e| anyhow::anyhow!("bad signing sk: {e}"))?;
    let pk = CryptoKey::from_bytes(&identity.signing_pk_bytes)
        .map_err(|e| anyhow::anyhow!("bad signing pk: {e}"))?;
    let mut signer = Dilithium2::new();
    signer.set_secret(sk);
    signer.set_public(pk);
    Ok(signer)
}

fn build_verifier(contact: &ContactRecord) -> Result<Key<{ Dilithium2::PUBLIC_KEY_SIZE }>> {
    CryptoKey::from_bytes(&contact.signing_pk_bytes)
        .map_err(|e| anyhow::anyhow!("bad contact signing pk: {e}"))
}

/// Concatenate slices for signing.
fn concat_for_sign(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|s| s.iter().copied()).collect()
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.context("read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        anyhow::bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.context("read frame body")?;
    Ok(buf)
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data).await.context("write frame")?;
    stream.flush().await.context("flush")?;
    Ok(())
}

/// Start a Tor hidden service listener.
pub async fn listen(
    port: u16,
    store: Store,
    event_tx: mpsc::UnboundedSender<LiveEvent>,
    cancel: CancellationToken,
) -> Result<(String, Option<tokio::process::Child>)> {
    let identity = store.load_identity()?
        .ok_or_else(|| anyhow::anyhow!("No identity found"))?;

    let tor_sk_bytes: [u8; 64] = identity.tor_sk_bytes.clone().try_into()
        .map_err(|_| anyhow::anyhow!("invalid tor secret key length"))?;
    let tor_sk = torut::onion::TorSecretKeyV3::from(tor_sk_bytes);
    let onion_addr = tor_sk.public().get_onion_address();

    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await
        .with_context(|| format!("bind to 127.0.0.1:{port}"))?;

    let mut tor_child = spawn_tor(&event_tx).await?;

    use torut::control::UnauthenticatedConn;
    let tor_stream = tokio::net::TcpStream::connect(TOR_CONTROL).await
        .context("connect to Tor control port")?;
    let mut uc = UnauthenticatedConn::new(tor_stream);
    let proto_info = uc.load_protocol_info().await
        .map_err(|e| anyhow::anyhow!("Tor protocol info: {e}"))?;
    let auth_data = proto_info.make_auth_data()
        .map_err(|e| anyhow::anyhow!("Tor auth data: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no supported Tor auth method"))?;
    uc.authenticate(&auth_data).await
        .map_err(|e| anyhow::anyhow!("Tor auth: {e}"))?;
    let mut ac = uc.into_authenticated().await;
    ac.set_async_event_handler(Some(|_| async { Ok(()) }));

    if let Err(e) = ac.add_onion_v3(
        &tor_sk,
        false, false, false,
        None,
        &mut [(port, std::net::SocketAddr::from(([127, 0, 0, 1], port)))].iter(),
    ).await {
        if let Some(ref mut child) = tor_child {
            let _ = child.kill().await;
        }
        return Err(anyhow::anyhow!("add_onion_v3: {e}"));
    }

    let addr_string = format!("{}:{port}", onion_addr);

    tokio::spawn(async move {
        let _ac = ac;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = listener.accept() => {
                    let (stream, _) = match result {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let store = store.clone();
                    let identity = identity.clone();
                    let event_tx = event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_incoming(stream, &store, &identity, &event_tx).await {
                            let _ = event_tx.send(LiveEvent::Error {
                                server_id: 0,
                                message: format!("share recv error: {e}"),
                            });
                        }
                    });
                }
            }
        }
    });

    Ok((addr_string, tor_child))
}

/// Receiver side of the Tor sharing protocol.
///
/// Protocol:
///   Step 1: read InviteMsg from A (proves A's intent, verifies A is known contact)
///   Step 2: generate ephemeral KEM keypair, sign (offer_id || kem_pk), send KemOffer to A
///   Step 3: read SharePacket from A, verify signature, decapsulate → shared_secret, decrypt data
async fn handle_incoming(
    mut stream: TcpStream,
    store: &Store,
    identity: &IdentityRecord,
    event_tx: &mpsc::UnboundedSender<LiveEvent>,
) -> Result<()> {
    // Step 1: read InviteMsg from A
    let frame = read_frame(&mut stream).await?;
    let invite: InviteMsg = decode_frame(&frame)?;

    let contact = store.load_contact(&invite.user_id)
        .with_context(|| format!("unknown contact: {}", invite.user_id))?;

    let contact_pk = build_verifier(&contact)?;
    let valid = Dilithium2::verify(&contact_pk, &invite.random_bytes, &invite.signature)
        .map_err(|e| anyhow::anyhow!("signature verify: {e}"))?;
    if !valid {
        anyhow::bail!("invalid invite signature from {}", invite.user_id);
    }

    // Step 2: generate ephemeral KEM keypair, create KemOffer, sign, send
    let kyber = Kyber512::new();
    let kem_pk_bytes = kyber.get_public().as_bytes().to_vec();

    let signer = build_signer(identity)?;
    let offer_sig = signer.sign(&kem_pk_bytes)
        .map_err(|e| anyhow::anyhow!("sign offer: {e}"))?;

    let kem_offer = KemOffer {
        user_id: identity.id.clone(),
        kem_pk: kem_pk_bytes,
        signature: offer_sig,
    };
    let offer_frame = encode_frame(&kem_offer)?;
    write_frame(&mut stream, &offer_frame).await?;

    // Step 3: read SharePacket from A
    let packet_frame = read_frame(&mut stream).await?;
    let packet: SharePacket = decode_frame(&packet_frame)?;

    let packet_sign_msg = concat_for_sign(&[&packet.kem_ct, &packet.ciphertext, &packet.nonce]);
    let valid = Dilithium2::verify(&contact_pk, &packet_sign_msg, &packet.signature)
        .map_err(|e| anyhow::anyhow!("verify packet: {e}"))?;
    if !valid {
        anyhow::bail!("invalid packet signature from {}", packet.user_id);
    }

    let shared_secret = kyber.decapsulate(&packet.kem_ct)
        .map_err(|e| anyhow::anyhow!("decapsulate: {e}"))?;

    let cipher = derive_aes_key(shared_secret.as_bytes())?;
    let plaintext = cipher.decrypt(&packet.nonce, &packet.ciphertext, b"share")
        .map_err(|e| anyhow::anyhow!("decrypt share: {e}"))?;
    let data = ShareData::from_bytes(&plaintext)?;

    let _ = event_tx.send(LiveEvent::ShareReceived(data));
    Ok(())
}

/// Sender side of the Tor sharing protocol.
///
/// Protocol:
///   Step 1: generate 32 random bytes, sign, send InviteMsg to B
///   Step 2: read KemOffer from B, verify signature
///   Step 3: encapsulate B's kem_pk → (shared_secret, kem_ct), encrypt data, sign, send SharePacket
pub async fn send_share(
    data: ShareData,
    contact: &ContactRecord,
    identity: &IdentityRecord,
    port: u16,
) -> Result<()> {
    let target = format!("{}:{port}", contact.onion_address.trim_end_matches('/'));

    let socks_stream = tokio_socks::tcp::Socks5Stream::connect(
        TOR_SOCKS, target.as_str(),
    ).await
        .with_context(|| format!("SOCKS5 connect to {target}"))?;

    let mut stream = socks_stream.into_inner();

    // Step 1: generate random invite, sign, send InviteMsg
    let random_bytes: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
    let signer = build_signer(identity)?;
    let invite_sig = signer.sign(&random_bytes)
        .map_err(|e| anyhow::anyhow!("sign invite: {e}"))?;

    let invite = InviteMsg {
        user_id: identity.id.clone(),
        random_bytes,
        signature: invite_sig,
    };
    let invite_frame = encode_frame(&invite)?;
    write_frame(&mut stream, &invite_frame).await?;

    // Step 2: read KemOffer from B, verify
    let offer_frame = read_frame(&mut stream).await?;
    let kem_offer: KemOffer = decode_frame(&offer_frame)?;

    let contact_pk = build_verifier(contact)?;
    let valid = Dilithium2::verify(&contact_pk, &kem_offer.kem_pk, &kem_offer.signature)
        .map_err(|e| anyhow::anyhow!("verify offer: {e}"))?;
    if !valid {
        anyhow::bail!("invalid KemOffer signature from {}", kem_offer.user_id);
    }

    // Step 3: encapsulate, encrypt, sign, send SharePacket
    let kem_pk: Key<{ Kyber512::PUBLIC_KEY_SIZE }> = CryptoKey::from_bytes(&kem_offer.kem_pk)
        .map_err(|e| anyhow::anyhow!("bad KEM pk: {e}"))?;
    let (shared_secret, kem_ct) = Kyber512::encapsulate(&kem_pk)
        .map_err(|e| anyhow::anyhow!("encapsulate: {e}"))?;

    let plaintext = data.to_bytes()?;
    let cipher = derive_aes_key(shared_secret.as_bytes())?;
    let nonce = Aes256Gcm::generate_nonce();
    let ciphertext = cipher.encrypt(&nonce, &plaintext, b"share")
        .map_err(|e| anyhow::anyhow!("encrypt share: {e}"))?;

    let packet_sign_msg = concat_for_sign(&[&kem_ct, &ciphertext, &nonce]);
    let packet_sig = signer.sign(&packet_sign_msg)
        .map_err(|e| anyhow::anyhow!("sign packet: {e}"))?;

    let packet = SharePacket {
        user_id: identity.id.clone(),
        kem_ct,
        ciphertext,
        nonce,
        signature: packet_sig,
    };
    let packet_frame = encode_frame(&packet)?;
    write_frame(&mut stream, &packet_frame).await?;

    Ok(())
}
