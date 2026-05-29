use std::sync::Arc;
use std::time::Instant;

use tonic::{Code, Request, Response, Status};

use crate::api::proto::app::stats::command::{
    stats_service_server::StatsService, GetAllOnlineUsersRequest, GetAllOnlineUsersResponse,
    GetStatsOnlineIpListResponse, GetStatsRequest, GetStatsResponse, GetUsersStatsRequest,
    GetUsersStatsResponse, QueryStatsRequest, QueryStatsResponse, Stat, SysStatsRequest,
    SysStatsResponse,
};
use crate::stats::{GetStatError, StatsRegistry};

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

fn unimplemented(method: &str) -> Status {
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
        let request = request.into_inner();
        match self.registry.get(&request.name, request.reset) {
            Ok(value) => Ok(Response::new(GetStatsResponse {
                stat: Some(Stat {
                    name: request.name,
                    value,
                }),
            })),
            Err(GetStatError::NotFound) => Err(Status::new(
                Code::NotFound,
                format!("{} not found.", request.name),
            )),
        }
    }

    async fn get_stats_online(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        Err(unimplemented("GetStatsOnline"))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let request = request.into_inner();
        let stat = self
            .registry
            .query(&request.pattern, request.reset)
            .into_iter()
            .map(|entry| Stat {
                name: entry.name,
                value: entry.value,
            })
            .collect();
        Ok(Response::new(QueryStatsResponse { stat }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        Ok(Response::new(SysStatsResponse {
            num_goroutine: 0,
            num_gc: 0,
            alloc: 0,
            total_alloc: 0,
            sys: 0,
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime: self.started_at.elapsed().as_secs() as u32,
        }))
    }

    async fn get_stats_online_ip_list(
        &self,
        _request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        Err(unimplemented("GetStatsOnlineIpList"))
    }

    async fn get_all_online_users(
        &self,
        _request: Request<GetAllOnlineUsersRequest>,
    ) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        Err(unimplemented("GetAllOnlineUsers"))
    }

    async fn get_users_stats(
        &self,
        _request: Request<GetUsersStatsRequest>,
    ) -> Result<Response<GetUsersStatsResponse>, Status> {
        Err(unimplemented("GetUsersStats"))
    }
}
