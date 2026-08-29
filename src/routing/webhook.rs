use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::api::proto::app::router::WebhookConfig;
use crate::routing::context::RouteContext;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

pub trait WebhookNotifier: Send + Sync {
    fn fire(&self, ctx: &RouteContext, outbound_tag: &str);
    fn close(&self);
}

struct HttpWebhook {
    endpoint: ParsedHttpUrl,
    headers: HashMap<String, String>,
    deduplication: u32,
    seen: Mutex<HashMap<String, i64>>,
    last_sweep: AtomicI64,
    closed: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl HttpWebhook {
    fn is_duplicate(&self, email: &str) -> bool {
        if self.deduplication == 0 || email.is_empty() {
            return false;
        }
        let now = unix_seconds();
        let ttl = i64::from(self.deduplication);
        let last = self.last_sweep.load(Ordering::Relaxed);
        if now - last >= ttl
            && self
                .last_sweep
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.seen
                .lock()
                .expect("webhook seen lock")
                .retain(|_, timestamp| now - *timestamp < ttl);
        }
        let mut seen = self.seen.lock().expect("webhook seen lock");
        match seen.get_mut(email) {
            Some(timestamp) if now - *timestamp < ttl => true,
            Some(timestamp) => {
                *timestamp = now;
                false
            }
            None => {
                seen.insert(email.to_string(), now);
                false
            }
        }
    }
}

impl WebhookNotifier for HttpWebhook {
    fn fire(&self, ctx: &RouteContext, outbound_tag: &str) {
        if self.closed.load(Ordering::Acquire) || self.is_duplicate(&ctx.user) {
            return;
        }
        let endpoint = self.endpoint.clone();
        let headers = self.headers.clone();
        let payload = build_webhook_payload(ctx, outbound_tag);
        let task = tokio::spawn(async move {
            let _ =
                tokio::time::timeout(WEBHOOK_TIMEOUT, post_json(endpoint, headers, payload)).await;
        });
        let mut tasks = self.tasks.lock().expect("webhook task lock");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        for task in self.tasks.lock().expect("webhook task lock").drain(..) {
            task.abort();
        }
        self.seen.lock().expect("webhook seen lock").clear();
    }
}

impl Drop for HttpWebhook {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

fn build_webhook_payload(ctx: &RouteContext, outbound_tag: &str) -> String {
    let source = ctx
        .source_ips
        .first()
        .map(|ip| socket_label(*ip, ctx.source_port));
    let destination = if !ctx.target_domain.is_empty() {
        Some(format_host_port(&ctx.target_domain, ctx.target_port))
    } else {
        ctx.target_ips
            .first()
            .map(|ip| socket_label(*ip, ctx.target_port))
    };
    let inbound_local = ctx
        .local_ips
        .first()
        .map(|ip| socket_label(*ip, ctx.local_port));
    serde_json::json!({
        "email": (!ctx.user.is_empty()).then_some(ctx.user.as_str()),
        "protocol": ctx.protocol,
        "network": ctx.network.as_str(),
        "source": source,
        "destination": destination,
        "originalTarget": serde_json::Value::Null,
        "routeTarget": serde_json::Value::Null,
        "inboundTag": ctx.inbound_tag,
        "inboundName": serde_json::Value::Null,
        "inboundLocal": inbound_local,
        "outboundTag": outbound_tag,
        "ts": unix_seconds(),
    })
    .to_string()
}

fn socket_label(ip: IpAddr, port: u16) -> String {
    std::net::SocketAddr::new(ip, port).to_string()
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn post_json(
    endpoint: ParsedHttpUrl,
    headers: HashMap<String, String>,
    body: String,
) -> std::io::Result<()> {
    let mut stream = tokio::net::TcpStream::connect((&*endpoint.host, endpoint.port)).await?;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        endpoint.path,
        endpoint.host,
        body.len()
    );
    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream.write_all(request.as_bytes()).await?;
    let mut response = [0_u8; 256];
    let _ = stream.read(&mut response).await;
    Ok(())
}

#[derive(Clone)]
struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedHttpUrl {
    fn parse(raw: &str) -> std::io::Result<Self> {
        let without_scheme = raw.strip_prefix("http://").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported webhook URL scheme",
            )
        })?;
        let (authority, path) = match without_scheme.split_once('/') {
            Some((authority, rest)) => (authority, format!("/{rest}")),
            None => (without_scheme, "/".to_string()),
        };
        let (host, port) = authority
            .rsplit_once(':')
            .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
            .unwrap_or((authority, 80));
        if host.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "webhook URL host is empty",
            ));
        }
        Ok(Self {
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            path,
        })
    }
}

pub fn compile_webhook(
    config: Option<&WebhookConfig>,
) -> Result<Option<Arc<dyn WebhookNotifier>>, String> {
    let Some(config) = config else {
        return Ok(None);
    };
    if config.url.is_empty() {
        return Ok(None);
    }
    let endpoint = ParsedHttpUrl::parse(&config.url).map_err(|err| err.to_string())?;
    Ok(Some(Arc::new(HttpWebhook {
        endpoint,
        headers: config.headers.clone(),
        deduplication: config.deduplication,
        seen: Mutex::new(HashMap::new()),
        last_sweep: AtomicI64::new(0),
        closed: AtomicBool::new(false),
        tasks: Mutex::new(Vec::new()),
    })))
}

pub fn close_webhooks(rules: &[super::compile::CompiledRule]) {
    for rule in rules {
        if let Some(webhook) = &rule.webhook {
            webhook.close();
        }
    }
}
