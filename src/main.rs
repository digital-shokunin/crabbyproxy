use libc::{c_uint, if_nametoindex, setsockopt, IPPROTO_IP};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::process::Command as Process;
use tokio::sync::RwLock;

const IP_BOUND_IF: i32 = 25; // macOS setsockopt constant

// ── Config ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DohConfig {
    servers: Vec<String>,
}

#[derive(Deserialize)]
struct ProxyConfig {
    socks_port: Option<u16>,
    pac_port: Option<u16>,
    domains: Vec<String>,
}

#[derive(Deserialize)]
struct Config {
    doh: DohConfig,
    proxy: ProxyConfig,
}

fn default_config() -> Config {
    Config {
        doh: DohConfig {
            servers: vec![
                "https://1.1.1.1/dns-query".into(),
                "https://8.8.8.8/dns-query".into(),
                "https://9.9.9.9:5053/dns-query".into(),
            ],
        },
        proxy: ProxyConfig {
            socks_port: Some(1080),
            pac_port: Some(1081),
            domains: vec![
                "*.youtube.com".into(),
                "youtube.com".into(),
                "*.googlevideo.com".into(),
                "*.ytimg.com".into(),
                "*.youtube-nocookie.com".into(),
                "youtube-nocookie.com".into(),
                "*.ggpht.com".into(),
                "*.googleapis.com".into(),
                "*.reddit.com".into(),
                "reddit.com".into(),
                "*.redd.it".into(),
                "*.redditstatic.com".into(),
                "*.hulu.com".into(),
                "hulu.com".into(),
                "*.hulustream.com".into(),
                "*.huluim.com".into(),
                "*.netflix.com".into(),
                "netflix.com".into(),
                "*.nflxvideo.net".into(),
                "*.nflximg.net".into(),
                "*.nflxso.net".into(),
                "*.nflxext.com".into(),
            ],
        },
    }
}

fn config_dir() -> std::path::PathBuf {
    let user_dir = dirs::home_dir()
        .map(|h| h.join(".config/crabbyproxy"))
        .unwrap_or_default();

    // Any known config file in user dir → use it
    if user_dir.join("config.toml").exists()
        || user_dir.join("proxy.pac").exists()
        || user_dir.join("doh.conf").exists()
    {
        return user_dir;
    }

    // Homebrew: /opt/homebrew/bin/../etc/crabbyproxy
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = exe.parent().and_then(|b| b.parent()) {
            let etc_dir = prefix.join("etc/crabbyproxy");
            if etc_dir.exists() {
                return etc_dir;
            }
        }
    }

    user_dir
}

fn load_config() -> Config {
    let path = config_dir().join("config.toml");
    if !path.exists() {
        return default_config();
    }
    match std::fs::read_to_string(&path) {
        Ok(s) => toml::from_str::<Config>(&s).unwrap_or_else(|e| {
            eprintln!("crabbyproxy: config.toml parse error: {e}, using defaults");
            default_config()
        }),
        Err(e) => {
            eprintln!("crabbyproxy: could not read config.toml: {e}, using defaults");
            default_config()
        }
    }
}

fn generate_pac(domains: &[String], socks_port: u16) -> String {
    if domains.is_empty() {
        return "function FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n".into();
    }
    let last = domains.len() - 1;
    let conditions: Vec<String> = domains
        .iter()
        .enumerate()
        .map(|(i, d)| match (i == 0, i == last) {
            (true, true) => format!("  if (shExpMatch(host, {d:?}))"),
            (true, false) => format!("  if (shExpMatch(host, {d:?}) ||"),
            (false, false) => format!("      shExpMatch(host, {d:?}) ||"),
            (false, true) => format!("      shExpMatch(host, {d:?}))"),
        })
        .collect();
    format!(
        "function FindProxyForURL(url, host) {{\n{}\n    return \"SOCKS5 127.0.0.1:{socks_port}\";\n  return \"DIRECT\";\n}}\n",
        conditions.join("\n")
    )
}

fn find_setpac_helper() -> Option<std::path::PathBuf> {
    // Next to binary (Homebrew: /opt/homebrew/bin/crabbyproxy-setpac)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            let p = bin_dir.join("crabbyproxy-setpac");
            if p.exists() {
                return Some(p);
            }
        }
    }
    // install.sh location
    dirs::home_dir()
        .map(|h| h.join(".local/bin/crabbyproxy-setpac"))
        .filter(|p| p.exists())
}

// ── DNS ───────────────────────────────────────────────────────────────────

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
        let ttl = ttl.max(30).min(300); // clamp 30s–5min
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        self.entries.write().await.insert(name, (ips, expires));
    }
}

async fn doh_resolve(
    client: &Client,
    name: &str,
    cache: &DnsCache,
    doh_servers: &[String],
) -> Option<Vec<IpAddr>> {
    if let Some(ips) = cache.get(name).await {
        return Some(ips);
    }

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
            Err(_) => continue,
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
            .filter(|a| a.rtype == 1)
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

// ── Interface binding ─────────────────────────────────────────────────────

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

// ── PAC server ────────────────────────────────────────────────────────────

async fn serve_pac(content: Arc<String>, pac_port: u16) {
    let bind_addr = format!("127.0.0.1:{pac_port}");
    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("crabbyproxy: PAC server failed to bind {bind_addr}: {e}");
            return;
        }
    };
    eprintln!("crabbyproxy: PAC server on http://{bind_addr}/proxy.pac");
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        let body = content.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = conn.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = conn.write_all(response.as_bytes()).await;
        });
    }
}

// ── SOCKS5 handler ────────────────────────────────────────────────────────

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
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
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
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };

    let ip = if is_domain {
        match doh_resolve(&http, &addr_str, &cache, &doh_servers)
            .await
            .and_then(|v| v.into_iter().next())
        {
            Some(ip) => ip,
            None => {
                client
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Ok(());
            }
        }
    } else {
        match addr_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                client
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Ok(());
            }
        }
    };

    let addr = SocketAddr::new(ip, port);

    // Re-detect interface per connection (handles Wi-Fi/Ethernet switching)
    let (_, if_index) = find_interface().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no physical interface available")
    })?;
    let socket = TcpSocket::new_v4()?;
    bind_to_interface(socket.as_raw_fd(), if_index)?;

    let remote = match tokio::time::timeout(Duration::from_secs(10), socket.connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            client
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };

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

// ── WireGuard watcher ─────────────────────────────────────────────────────

async fn get_primary_interface() -> Option<String> {
    let mut child = Process::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin
            .write_all(b"open\nshow State:/Network/Global/IPv4\nquit\n")
            .await;
    }

    let output = child.wait_with_output().await.ok()?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(rest) = line.trim().strip_prefix("PrimaryInterface :") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

async fn set_scutil_proxy() {
    let Some(helper) = find_setpac_helper() else {
        eprintln!("crabbyproxy: crabbyproxy-setpac not found, Chrome proxy won't be set");
        return;
    };
    if let Ok(mut child) = Process::new("sudo")
        .arg(&helper)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let _ = child.wait().await;
    }
}

async fn watch_wireguard_proxy() {
    eprintln!("crabbyproxy: watching for WireGuard, will set PAC in SCDynamicStore");
    let mut last_was_vpn = false;
    loop {
        let primary = get_primary_interface().await.unwrap_or_default();
        let is_vpn = primary.starts_with("utun");

        if is_vpn && !last_was_vpn {
            eprintln!("crabbyproxy: WireGuard active on {primary}, setting PAC in SCDynamicStore");
            set_scutil_proxy().await;
        }
        last_was_vpn = is_vpn;

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = load_config();
    let socks_port = config.proxy.socks_port.unwrap_or(1080);
    let pac_port = config.proxy.pac_port.unwrap_or(1081);
    let doh_servers = Arc::new(config.doh.servers);

    let pac_content = Arc::new(generate_pac(&config.proxy.domains, socks_port));

    let addr = format!("127.0.0.1:{socks_port}");
    let listener = TcpListener::bind(&addr).await?;

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

    tokio::spawn(serve_pac(pac_content, pac_port));
    tokio::spawn(watch_wireguard_proxy());

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
