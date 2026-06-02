//! Xray-compatible gRPC stats API CLI client.

use std::time::Duration;

use tonic::transport::Endpoint;

use crate::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use crate::api::proto::app::stats::command::{GetStatsRequest, QueryStatsRequest};
use crate::api::{validate_stats_options, ApiError};
use crate::cli::StatsApiOptions;

fn endpoint_url(server: &str) -> String {
    if server.starts_with("http://") || server.starts_with("https://") {
        server.to_string()
    } else {
        format!("http://{server}")
    }
}

fn map_tonic_error(err: tonic::Status, rpc: &str) -> ApiError {
    ApiError::new(format!(
        "failed to call StatsService.{rpc}: {}",
        err.message()
    ))
}

/// Query all stats matching `pattern` (Xray `api statsquery`).
pub async fn stats_query(opts: StatsApiOptions) -> Result<(), ApiError> {
    validate_stats_options("statsquery", &opts)?;
    let response = query_stats_async(opts).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

/// Fetch a single stat counter (Xray `api stats`).
pub async fn get_stats(opts: StatsApiOptions) -> Result<(), ApiError> {
    validate_stats_options("stats", &opts)?;
    let response = get_stats_async(opts).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".into())
    );
    Ok(())
}

async fn get_stats_async(opts: StatsApiOptions) -> Result<serde_json::Value, ApiError> {
    let channel = connect(&opts).await?;
    let mut client = StatsServiceClient::new(channel);
    let name = opts.name.clone().unwrap_or_default();
    match client
        .get_stats(GetStatsRequest {
            name,
            reset: opts.reset,
        })
        .await
    {
        Ok(resp) => Ok(stat_to_json(resp.into_inner().stat)),
        Err(status) => Err(map_tonic_error(status, "GetStats")),
    }
}

async fn query_stats_async(opts: StatsApiOptions) -> Result<serde_json::Value, ApiError> {
    let channel = connect(&opts).await?;
    let mut client = StatsServiceClient::new(channel);
    let pattern = opts.pattern.clone().unwrap_or_default();
    match client
        .query_stats(QueryStatsRequest {
            pattern,
            reset: opts.reset,
        })
        .await
    {
        Ok(resp) => {
            let stats: Vec<_> = resp
                .into_inner()
                .stat
                .into_iter()
                .map(|entry| {
                    serde_json::json!({
                        "name": entry.name,
                        "value": entry.value,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "stat": stats }))
        }
        Err(status) => Err(map_tonic_error(status, "QueryStats")),
    }
}

async fn connect(opts: &StatsApiOptions) -> Result<tonic::transport::Channel, ApiError> {
    let url = endpoint_url(&opts.server);
    Endpoint::from_shared(url)
        .map_err(|e| ApiError::new(format!("invalid api server address: {e}")))?
        .connect_timeout(Duration::from_secs(opts.timeout_secs.max(1)))
        .connect()
        .await
        .map_err(|e| ApiError::new(format!("failed to dial {}: {e}", opts.server)))
}

fn stat_to_json(stat: Option<crate::api::proto::app::stats::command::Stat>) -> serde_json::Value {
    match stat {
        Some(stat) => serde_json::json!({
            "stat": {
                "name": stat.name,
                "value": stat.value,
            }
        }),
        None => serde_json::json!({ "stat": null }),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/api/client.rs"]
mod tests;
