use rustls::pki_types::pem::PemObject;
use rustls::{ClientConnection,pki_types::CertificateDer, RootCertStore, ServerConnection, StreamOwned, pki_types::ServerName};
use std::io::{Read, Write};
use std::sync::Arc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::certs;

// You can add here other imports from std or crates listed in Cargo.toml.

// The below `PhantomData` marker is here only to suppress the "unused type
// parameter" error. Remove it when you implement your solution:
use std::marker::PhantomData;

type HmacSha256 = Hmac<Sha256>;
pub struct SecureClient<L: Read + Write> {
    // Add here any fields you need.
    phantom: PhantomData<L>,
    hmac_key: Vec<u8>,
    stream: StreamOwned<ClientConnection,L>,
}

pub struct SecureServer<L: Read + Write> {
    // Add here any fields you need.
    phantom: PhantomData<L>,
}

impl<L: Read + Write> SecureClient<L> {
    /// Creates a new instance of `SecureClient`.
    ///
    /// `SecureClient` communicates with `SecureServer` via `link`.
    /// The messages include a HMAC tag calculated using `hmac_key`.
    /// A certificate of `SecureServer` is signed by `root_cert`.
    /// We are connecting with `server_hostname`.
    pub fn new(
        link: L,
        hmac_key: &[u8],
        root_cert: &str,
        server_hostname: ServerName<'static>,
    ) -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(rustls::pki_types::CertificateDer::from_pem_slice(
            root_cert.as_bytes(),
        ));
        
        let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

        let connection =
        ClientConnection::new(Arc::new(client_config), server_hostname).unwrap();

        SecureClient {
            phantom: PhantomData,
            hmac_key: hmac_key.to_vec(),
            stream: StreamOwned::new(connection, link),
        }
    }

    /// Sends the data to the server. The sent message follows the
    /// format specified in the description of the assignment.
    pub fn send_msg(&mut self, data: Vec<u8>) {
        assert!(data.len() <= u32::MAX as usize, "message too large");

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        mac.update(&data);
        let hmac_tag = mac.finalize().into_bytes();

        let len = (data.len() as u32).to_be_bytes();
        
        let mut payload: Vec<u8> = Vec::with_capacity(4+data.len()+hmac_tag.len());

        payload.extend_from_slice(&len);
        payload.extend_from_slice(&data);
        payload.extend_from_slice(&hmac_tag);

        self.stream.write_all(&payload).unwrap();
    }
}

impl<L: Read + Write> SecureServer<L> {
    /// Creates a new instance of `SecureServer`.
    ///
    /// `SecureServer` receives messages from `SecureClients` via `link`.
    /// HMAC tags of the messages are verified against `hmac_key`.
    /// The private key of the `SecureServer`'s certificate is `server_private_key`,
    /// and the full certificate chain is `server_full_chain`.
    pub fn new(
        link: L,
        hmac_key: &[u8],
        server_private_key: &str,
        server_full_chain: &str,
    ) -> Self {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::from_pem_slice(
            server_full_chain.as_bytes()
        ).into_iter().map(|c| c.into_owned()).collect();

        let mut keys = rustls::pki_types::PrivateKeyDer::from_pem_slice(server_private_key.as_bytes())
            .expect("invalid private key PEM");
        let key = keys.remove(0);

        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("bad cert or key");

        let conn = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        let stream = StreamOwned::new(conn, link);

        SecureServer {
            phantom: PhantomData,
            hmac_key: hmac_key.to_vec(),
            stream,
        }
    }

    /// Receives the next incoming message and returns the message's content
    /// (i.e., without the message size and without the HMAC tag) if the
    /// message's HMAC tag is correct. Otherwise, returns `SecureServerError`.
    pub fn recv_message(&mut self) -> Result<Vec<u8>, SecureServerError> {
        unimplemented!()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SecureServerError {
    /// The HMAC tag of a message is invalid.
    InvalidHmac,
}

// You can add any private types, structs, consts, functions, methods, etc., you need.
