use std::sync::Arc;
use std::time::Instant;

use tonic::{Code, Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, log_rpc_ok, rpc_remote_addr};
use crate::api::proto::app::stats::command::{
    stats_service_server::StatsService, GetAllOnlineUsersRequest, GetAllOnlineUsersResponse,
    GetStatsOnlineIpListResponse, GetStatsRequest, GetStatsResponse, GetUsersStatsRequest,
    GetUsersStatsResponse, QueryStatsRequest, QueryStatsResponse, Stat, SysStatsRequest,
    SysStatsResponse,
};
use crate::stats::{GetStatError, StatsRegistry};

const SERVICE: &str = "StatsService";

#[derive(Debug)]
pub struct StatsServiceImpl {
    registry: Arc<StatsRegistry>,
    started_at: Instant,
}

impl StatsServiceImpl {
    pub fn new(registry: Arc<StatsRegistry>) -> Self {
        Self {
            registry,
            started_at: Instant::now(),
        }
    }
}

fn unimplemented(method: &str, remote: &str) -> Status {
    log_rpc_err(SERVICE, method, remote, "UNIMPLEMENTED");
    Status::unimplemented(format!(
        "StatsService.{method} is not implemented in rust-xray"
    ))
}

#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetStats", &remote);
        let request = request.into_inner();
        match self.registry.get(&request.name, request.reset) {
            Ok(value) => {
                log_rpc_ok(
                    SERVICE,
                    "GetStats",
                    &remote,
                    &format!("name={} value={value}", request.name),
                );
                Ok(Response::new(GetStatsResponse {
                    stat: Some(Stat {
                        name: request.name,
                        value,
                    }),
                }))
            }
            Err(GetStatError::NotFound) => {
                log_rpc_err(SERVICE, "GetStats", &remote, "not found");
                Err(Status::new(
                    Code::NotFound,
                    format!("{} not found.", request.name),
                ))
            }
        }
    }

    async fn get_stats_online(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        Err(unimplemented("GetStatsOnline", &rpc_remote_addr(&request)))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "QueryStats", &remote);
        let request = request.into_inner();
        let stat: Vec<Stat> = self
            .registry
            .query(&request.pattern, request.reset)
            .into_iter()
            .map(|entry| Stat {
                name: entry.name,
                value: entry.value,
            })
            .collect();
        log_rpc_ok(
            SERVICE,
            "QueryStats",
            &remote,
            &format!("pattern={} count={}", request.pattern, stat.len()),
        );
        Ok(Response::new(QueryStatsResponse { stat }))
    }

    async fn get_sys_stats(
        &self,
        request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetSysStats", &remote);
        let _ = request.into_inner();
        let uptime = self.started_at.elapsed().as_secs() as u32;
        let response = SysStatsResponse {
            num_goroutine: 0,
            num_gc: 0,
            alloc: 0,
            total_alloc: 0,
            sys: 0,
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime,
        };
        log_rpc_ok(
            SERVICE,
            "GetSysStats",
            &remote,
            &format!("uptime={uptime} alloc=0 sys=0"),
        );
        Ok(Response::new(response))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        Err(unimplemented(
            "GetStatsOnlineIpList",
            &rpc_remote_addr(&request),
        ))
    }

    async fn get_all_online_users(
        &self,
        request: Request<GetAllOnlineUsersRequest>,
    ) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        Err(unimplemented(
            "GetAllOnlineUsers",
            &rpc_remote_addr(&request),
        ))
    }

    async fn get_users_stats(
        &self,
        request: Request<GetUsersStatsRequest>,
    ) -> Result<Response<GetUsersStatsResponse>, Status> {
        Err(unimplemented("GetUsersStats", &rpc_remote_addr(&request)))
    }
}
