use std::collections::BTreeSet;
use std::io::{self, Read};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
pub enum OriseekError {
    #[error("resolver init failed: {0}")]
    ResolverInit(String),
    #[error("stdin read failed: {0}")]
    Stdin(String),
    #[error("task join failed: {0}")]
    Join(String),
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsRecordSet {
    #[serde(rename = "A")]
    pub a: Vec<String>,
    #[serde(rename = "AAAA")]
    pub aaaa: Vec<String>,
    #[serde(rename = "MX")]
    pub mx: Vec<String>,
    #[serde(rename = "NS")]
    pub ns: Vec<String>,
    #[serde(rename = "CNAME")]
    pub cname: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsResolutionLine {
    pub fqdn: String,
    pub registered: bool,
    pub dns: DnsRecordSet,
    pub lookup_ms: u128,
    pub errors: Vec<String>,
}

pub fn read_domains_from_stdin() -> Result<Vec<String>, OriseekError> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| OriseekError::Stdin(e.to_string()))?;
    Ok(stdin
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_lowercase)
        .collect())
}

pub fn normalize_domains(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for item in items {
        let fqdn = item.trim().trim_end_matches('.').to_lowercase();
        if !fqdn.is_empty() {
            seen.insert(fqdn);
        }
    }
    seen.into_iter().collect()
}

async fn lookup_with_timeout<T, E, F>(
    future: F,
    timeout_duration: Duration,
    label: &str,
) -> Result<T, String>
where
    E: std::fmt::Display,
    F: std::future::Future<Output = Result<T, E>>,
{
    match timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(format!("{label}:{err}")),
        Err(_) => Err(format!("{label}:timeout")),
    }
}

fn is_registered(dns: &DnsRecordSet) -> bool {
    !(dns.a.is_empty()
        && dns.aaaa.is_empty()
        && dns.mx.is_empty()
        && dns.ns.is_empty()
        && dns.cname.is_empty())
}

fn normalize_record(value: String) -> String {
    value.trim_end_matches('.').to_string()
}

fn is_empty_lookup_error(err: &str) -> bool {
    err.contains("no records found")
}

pub async fn resolve_one(
    resolver: TokioResolver,
    fqdn: String,
    timeout_duration: Duration,
) -> DnsResolutionLine {
    let started = Instant::now();
    let query = format!("{fqdn}.");
    let mut dns = DnsRecordSet::default();
    let mut errors = Vec::new();

    match lookup_with_timeout(resolver.ipv4_lookup(query.as_str()), timeout_duration, "A").await {
        Ok(lookup) => dns.a = lookup.iter().map(|item| normalize_record(item.to_string())).collect(),
        Err(err) => {
            if !is_empty_lookup_error(&err) {
                errors.push(err);
            }
        }
    }

    match lookup_with_timeout(resolver.ipv6_lookup(query.as_str()), timeout_duration, "AAAA").await {
        Ok(lookup) => dns.aaaa = lookup.iter().map(|item| normalize_record(item.to_string())).collect(),
        Err(err) => {
            if !is_empty_lookup_error(&err) {
                errors.push(err);
            }
        }
    }

    match lookup_with_timeout(resolver.mx_lookup(query.as_str()), timeout_duration, "MX").await {
        Ok(lookup) => dns.mx = lookup.iter().map(|item| normalize_record(item.to_string())).collect(),
        Err(err) => {
            if !is_empty_lookup_error(&err) {
                errors.push(err);
            }
        }
    }

    match lookup_with_timeout(resolver.ns_lookup(query.as_str()), timeout_duration, "NS").await {
        Ok(lookup) => dns.ns = lookup.iter().map(|item| normalize_record(item.to_string())).collect(),
        Err(err) => {
            if !is_empty_lookup_error(&err) {
                errors.push(err);
            }
        }
    }

    match lookup_with_timeout(
        resolver.lookup(query.as_str(), RecordType::CNAME),
        timeout_duration,
        "CNAME",
    )
    .await
    {
        Ok(lookup) => dns.cname = lookup.iter().map(|item| normalize_record(item.to_string())).collect(),
        Err(err) => {
            if !is_empty_lookup_error(&err) {
                errors.push(err);
            }
        }
    }

    DnsResolutionLine {
        fqdn,
        registered: is_registered(&dns),
        dns,
        lookup_ms: started.elapsed().as_millis(),
        errors,
    }
}

pub async fn resolve_batch(
    domains: Vec<String>,
    concurrency: usize,
    timeout_duration: Duration,
) -> Result<Vec<DnsResolutionLine>, OriseekError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| OriseekError::ResolverInit(e.to_string()))?
        .build();
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut join_set = JoinSet::new();

    for fqdn in domains {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| OriseekError::Join(e.to_string()))?;
        let resolver = resolver.clone();
        join_set.spawn(async move { resolve_with_permit(resolver, fqdn, timeout_duration, permit).await });
    }

    let mut out = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(line) => out.push(line),
            Err(err) => return Err(OriseekError::Join(err.to_string())),
        }
    }
    out.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));
    Ok(out)
}

async fn resolve_with_permit(
    resolver: TokioResolver,
    fqdn: String,
    timeout_duration: Duration,
    _permit: OwnedSemaphorePermit,
) -> DnsResolutionLine {
    resolve_one(resolver, fqdn, timeout_duration).await
}

#[cfg(test)]
mod tests {
    use super::normalize_domains;

    #[test]
    fn normalize_domains_deduplicates() {
        let items = vec![
            "Example.com".to_string(),
            "example.com.".to_string(),
            "test.example.com".to_string(),
        ];
        let normalized = normalize_domains(items);
        assert_eq!(normalized, vec!["example.com".to_string(), "test.example.com".to_string()]);
    }
}
