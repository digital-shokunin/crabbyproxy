use libc::{c_uint, if_nametoindex, setsockopt, IPPROTO_IP};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::RwLock;

const IP_BOUND_IF: i32 = 25; // macOS setsockopt constant
const DEFAULT_DOH_SERVERS: &[&str] = &[
    "https://1.1.1.1/dns-query",       // Cloudflare
    "https://8.8.8.8/dns-query",       // Google
    "https://9.9.9.9:5053/dns-query",  // Quad9
];

fn load_doh_servers() -> Vec<String> {
    let config_path = dirs::home_dir()
        .map(|h| h.join(".config/crabbyproxy/doh.conf"))
        .unwrap_or_default();

    if config_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            let servers: Vec<String> = contents
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect();
            if !servers.is_empty() {
                return servers;
            }
        }
    }

    DEFAULT_DOH_SERVERS.iter().map(|s| s.to_string()).collect()
}

// Cloudflare DoH JSON response
#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
    #[serde(rename = "TTL")]
    ttl: u32,
}

struct DnsCache {
    entries: RwLock<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    async fn get(&self, name: &str) -> Option<Vec<IpAddr>> {
        let entries = self.entries.read().await;
        if let Some((ips, expires)) = entries.get(name) {
            if Instant::now() < *expires {
                return Some(ips.clone());
            }
        }
        None
    }

    async fn set(&self, name: String, ips: Vec<IpAddr>, ttl: u32) {
        let ttl = ttl.max(30).min(300); // clamp 30s-5min
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        self.entries.write().await.insert(name, (ips, expires));
    }
}

async fn doh_resolve(client: &Client, name: &str, cache: &DnsCache, doh_servers: &[String]) -> Option<Vec<IpAddr>> {
    // Check cache first
    if let Some(ips) = cache.get(name).await {
        return Some(ips);
    }

    // Try each DoH server with fallback
    for doh_url in doh_servers {
        let resp = client
            .get(doh_url)
            .header("Accept", "application/dns-json")
            .query(&[("name", name), ("type", "A")])
            .timeout(Duration::from_secs(3))
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(_) => continue, // try next server
        };

        let parsed = match resp.json::<DohResponse>().await {
            Ok(p) => p,
            Err(_) => continue,
        };

        let answers = match parsed.answer {
            Some(a) => a,
            None => continue,
        };

        let mut min_ttl = 300u32;
        let ips: Vec<IpAddr> = answers
            .iter()
            .filter(|a| a.rtype == 1) // A records only
            .filter_map(|a| {
                min_ttl = min_ttl.min(a.ttl);
                a.data.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
            })
            .collect();

        if !ips.is_empty() {
            cache.set(name.to_string(), ips.clone(), min_ttl).await;
            return Some(ips);
        }
    }

    None
}

fn bind_to_interface(fd: i32, if_index: c_uint) -> std::io::Result<()> {
    let ret = unsafe {
        setsockopt(
            fd,
            IPPROTO_IP,
            IP_BOUND_IF,
            &if_index as *const c_uint as *const _,
            std::mem::size_of::<c_uint>() as u32,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn get_if_index(name: &str) -> Option<c_uint> {
    let cname = CString::new(name).ok()?;
    let idx = unsafe { if_nametoindex(cname.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

fn find_interface() -> Option<(String, c_uint)> {
    for iface in &["en0", "en6", "en1"] {
        if let Some(idx) = get_if_index(iface) {
            return Some((iface.to_string(), idx));
        }
    }
    None
}

async fn serve_pac_file(pac_path: std::path::PathBuf) {
    let listener = match TcpListener::bind("127.0.0.1:1081").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("crabbyproxy: PAC server failed to bind port 1081: {e}");
            return;
        }
    };
    eprintln!("crabbyproxy: PAC server on http://127.0.0.1:1081/proxy.pac");
    loop {
        let Ok((mut conn, _)) = listener.accept().await else { continue };
        let pac_path = pac_path.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf).await;
            let body = std::fs::read_to_string(&pac_path).unwrap_or_default();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = conn.write_all(response.as_bytes()).await;
        });
    }
}

async fn relay(mut a: TcpStream, mut b: TcpStream) {
    let (mut ar, mut aw) = a.split();
    let (mut br, mut bw) = b.split();
    tokio::select! {
        _ = io::copy(&mut ar, &mut bw) => {}
        _ = io::copy(&mut br, &mut aw) => {}
    }
}

async fn handle_client(
    mut client: TcpStream,
    http: Arc<Client>,
    cache: Arc<DnsCache>,
    doh_servers: Arc<Vec<String>>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 512];

    // SOCKS5 greeting
    let n = client.read(&mut buf).await?;
    if n < 3 || buf[0] != 0x05 {
        return Ok(());
    }
    client.write_all(&[0x05, 0x00]).await?;

    // Connection request
    let n = client.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
        client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    }

    let (addr_str, port, is_domain) = match buf[3] {
        0x01 => {
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (ip, port, false)
        }
        0x03 => {
            let dlen = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
            let port = u16::from_be_bytes([buf[5 + dlen], buf[6 + dlen]]);
            (domain, port, true)
        }
        _ => {
            client.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };

    // Resolve via DoH for domains, direct parse for IPs
    let ip = if is_domain {
        let ips = doh_resolve(&http, &addr_str, &cache, &doh_servers).await;
        match ips.and_then(|v| v.into_iter().next()) {
            Some(ip) => ip,
            None => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Ok(());
            }
        }
    } else {
        match addr_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Ok(());
            }
        }
    };

    let addr = SocketAddr::new(ip, port);

    // Connect via bound interface (re-detect per connection)
    let (_, if_index) = find_interface().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no physical interface available")
    })?;
    let socket = TcpSocket::new_v4()?;
    bind_to_interface(socket.as_raw_fd(), if_index)?;

    let remote = match tokio::time::timeout(Duration::from_secs(10), socket.connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            client.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(());
        }
    };

    // Success
    let bind = remote.local_addr()?;
    let mut resp = vec![0x05, 0x00, 0x00, 0x01];
    if let SocketAddr::V4(v4) = bind {
        resp.extend_from_slice(&v4.ip().octets());
        resp.extend_from_slice(&v4.port().to_be_bytes());
    }
    client.write_all(&resp).await?;

    relay(client, remote).await;
    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = "127.0.0.1:1080";
    let listener = TcpListener::bind(addr).await?;

    let doh_servers = Arc::new(load_doh_servers());
    let http = Arc::new(
        Client::builder()
            .use_rustls_tls()
            .build()
            .expect("failed to build HTTP client"),
    );
    let cache = Arc::new(DnsCache::new());

    let iface_info = find_interface()
        .map(|(name, idx)| format!("{name} (index {idx})"))
        .unwrap_or_else(|| "none (will detect per connection)".to_string());

    eprintln!(
        "crabbyproxy: SOCKS5 on {addr}, outbound via {iface_info}, DoH servers: {}",
        doh_servers.join(", ")
    );

    let pac_path = dirs::home_dir()
        .map(|h| h.join(".config/crabbyproxy/proxy.pac"))
        .unwrap_or_default();
    tokio::spawn(serve_pac_file(pac_path));

    loop {
        let (client, _) = listener.accept().await?;
        let http = http.clone();
        let cache = cache.clone();
        let doh_servers = doh_servers.clone();
        tokio::spawn(async move {
            let _ = handle_client(client, http, cache, doh_servers).await;
        });
    }
}
