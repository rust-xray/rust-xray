use tonic::{Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, rpc_remote_addr};
use crate::api::proto::app::router::command::{
    routing_service_server::RoutingService, AddRuleRequest, AddRuleResponse,
    GetBalancerInfoRequest, GetBalancerInfoResponse, ListRuleRequest, ListRuleResponse,
    OverrideBalancerTargetRequest, OverrideBalancerTargetResponse, RemoveRuleRequest,
    RemoveRuleResponse, RoutingContext, SubscribeRoutingStatsRequest, TestRouteRequest,
};

const SERVICE: &str = "RoutingService";

#[derive(Debug, Default)]
pub struct RoutingServiceImpl;

fn unimplemented(method: &str, remote: &str) -> Status {
    log_rpc_err(SERVICE, method, remote, "UNIMPLEMENTED");
    Status::unimplemented(format!(
        "RoutingService.{method} is not implemented in rust-xray"
    ))
}

#[tonic::async_trait]
impl RoutingService for RoutingServiceImpl {
    type SubscribeRoutingStatsStream =
        tokio_stream::wrappers::ReceiverStream<Result<RoutingContext, Status>>;

    async fn subscribe_routing_stats(
        &self,
        request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "SubscribeRoutingStats", &remote);
        Err(unimplemented("SubscribeRoutingStats", &remote))
    }

    async fn test_route(
        &self,
        request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "TestRoute", &remote);
        Err(unimplemented("TestRoute", &remote))
    }

    async fn get_balancer_info(
        &self,
        request: Request<GetBalancerInfoRequest>,
    ) -> Result<Response<GetBalancerInfoResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetBalancerInfo", &remote);
        Err(unimplemented("GetBalancerInfo", &remote))
    }

    async fn override_balancer_target(
        &self,
        request: Request<OverrideBalancerTargetRequest>,
    ) -> Result<Response<OverrideBalancerTargetResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "OverrideBalancerTarget", &remote);
        Err(unimplemented("OverrideBalancerTarget", &remote))
    }

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<AddRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AddRule", &remote);
        Err(unimplemented("AddRule", &remote))
    }

    async fn remove_rule(
        &self,
        request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RemoveRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RemoveRule", &remote);
        Err(unimplemented("RemoveRule", &remote))
    }

    async fn list_rule(
        &self,
        request: Request<ListRuleRequest>,
    ) -> Result<Response<ListRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "ListRule", &remote);
        Err(unimplemented("ListRule", &remote))
    }
}
