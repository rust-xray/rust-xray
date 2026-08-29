use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tonic::{Code, Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, log_rpc_ok, rpc_remote_addr};
use crate::api::proto::app::stats::command::{
    stats_service_server::StatsService, GetAllOnlineUsersRequest, GetAllOnlineUsersResponse,
    GetStatsOnlineIpListResponse, GetStatsRequest, GetStatsResponse, GetUsersStatsRequest,
    GetUsersStatsResponse, OnlineIpEntry, QueryStatsRequest, QueryStatsResponse, Stat,
    SysStatsRequest, SysStatsResponse, TrafficUserStat, UserStat,
};
use crate::stats::{parse_user_online_email, GetStatError, StatsRegistry};

const SERVICE: &str = "StatsService";

const USER_TRAFFIC_PREFIX: &str = "user>>>";
const USER_UPLINK_SUFFIX: &str = ">>>traffic>>>uplink";
const USER_DOWNLINK_SUFFIX: &str = ">>>traffic>>>downlink";

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

fn not_found(name: &str) -> Status {
    Status::new(Code::NotFound, format!("{name} not found."))
}

fn parse_user_traffic_counter(name: &str) -> Option<(String, bool)> {
    if let Some(email) = name
        .strip_prefix(USER_TRAFFIC_PREFIX)
        .and_then(|rest| rest.strip_suffix(USER_UPLINK_SUFFIX))
    {
        return Some((email.to_string(), true));
    }
    name.strip_prefix(USER_TRAFFIC_PREFIX)
        .and_then(|rest| rest.strip_suffix(USER_DOWNLINK_SUFFIX))
        .map(|email| (email.to_string(), false))
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
                Err(not_found(&request.name))
            }
        }
    }

    async fn get_stats_online(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetStatsOnline", &remote);
        let request = request.into_inner();
        let Some(map) = self.registry.get_online_map(&request.name) else {
            log_rpc_err(SERVICE, "GetStatsOnline", &remote, "not found");
            return Err(not_found(&request.name));
        };
        let value = map.count();
        log_rpc_ok(
            SERVICE,
            "GetStatsOnline",
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
        log_rpc_ok(SERVICE, "GetSysStats", &remote, &format!("uptime={uptime}"));
        Ok(Response::new(response))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetStatsOnlineIpList", &remote);
        let request = request.into_inner();
        let Some(map) = self.registry.get_online_map(&request.name) else {
            log_rpc_err(SERVICE, "GetStatsOnlineIpList", &remote, "not found");
            return Err(not_found(&request.name));
        };
        let mut ips = HashMap::new();
        map.for_each(|ip, last_seen| {
            ips.insert(ip.to_string(), last_seen);
            true
        });
        Ok(Response::new(GetStatsOnlineIpListResponse {
            name: request.name,
            ips,
        }))
    }

    async fn get_all_online_users(
        &self,
        request: Request<GetAllOnlineUsersRequest>,
    ) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetAllOnlineUsers", &remote);
        let _ = request.into_inner();
        Ok(Response::new(GetAllOnlineUsersResponse {
            users: self.registry.get_all_online_users(),
        }))
    }

    async fn get_users_stats(
        &self,
        request: Request<GetUsersStatsRequest>,
    ) -> Result<Response<GetUsersStatsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetUsersStats", &remote);
        let request = request.into_inner();
        let mut user_map: HashMap<String, UserStat> = HashMap::new();

        self.registry.visit_online_maps(|name, map| {
            if map.count() == 0 {
                return true;
            }
            let Some(email) = parse_user_online_email(name) else {
                return true;
            };
            let mut user = UserStat {
                email: email.to_string(),
                ips: Vec::new(),
                traffic: None,
            };
            map.for_each(|ip, last_seen| {
                user.ips.push(OnlineIpEntry {
                    ip: ip.to_string(),
                    last_seen,
                });
                true
            });
            if !user.ips.is_empty() {
                user_map.insert(email.to_string(), user);
            }
            true
        });

        if request.include_traffic {
            for user in user_map.values_mut() {
                user.traffic = Some(TrafficUserStat {
                    uplink: 0,
                    downlink: 0,
                });
            }
            self.registry.visit_counters(|name, counter| {
                let Some((email, is_uplink)) = parse_user_traffic_counter(name) else {
                    return true;
                };
                let Some(user) = user_map.get_mut(&email) else {
                    return true;
                };
                let Some(traffic) = user.traffic.as_mut() else {
                    return true;
                };
                let value = if request.reset {
                    counter.reset()
                } else {
                    counter.value()
                };
                if is_uplink {
                    traffic.uplink = value;
                } else {
                    traffic.downlink = value;
                }
                true
            });
        }

        Ok(Response::new(GetUsersStatsResponse {
            users: user_map.into_values().collect(),
        }))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/api/stats.rs"]
mod tests;
