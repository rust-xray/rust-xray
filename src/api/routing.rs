use tonic::{Request, Response, Status};

use crate::api::proto::app::router::command::{
    routing_service_server::RoutingService, AddRuleRequest, AddRuleResponse,
    GetBalancerInfoRequest, GetBalancerInfoResponse, ListRuleRequest, ListRuleResponse,
    OverrideBalancerTargetRequest, OverrideBalancerTargetResponse, RemoveRuleRequest,
    RemoveRuleResponse, RoutingContext, SubscribeRoutingStatsRequest, TestRouteRequest,
};

#[derive(Debug, Default)]
pub struct RoutingServiceImpl;

fn unimplemented(method: &str) -> Status {
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
        _request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        Err(unimplemented("SubscribeRoutingStats"))
    }

    async fn test_route(
        &self,
        _request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        Err(unimplemented("TestRoute"))
    }

    async fn get_balancer_info(
        &self,
        _request: Request<GetBalancerInfoRequest>,
    ) -> Result<Response<GetBalancerInfoResponse>, Status> {
        Err(unimplemented("GetBalancerInfo"))
    }

    async fn override_balancer_target(
        &self,
        _request: Request<OverrideBalancerTargetRequest>,
    ) -> Result<Response<OverrideBalancerTargetResponse>, Status> {
        Err(unimplemented("OverrideBalancerTarget"))
    }

    async fn add_rule(
        &self,
        _request: Request<AddRuleRequest>,
    ) -> Result<Response<AddRuleResponse>, Status> {
        Err(unimplemented("AddRule"))
    }

    async fn remove_rule(
        &self,
        _request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RemoveRuleResponse>, Status> {
        Err(unimplemented("RemoveRule"))
    }

    async fn list_rule(
        &self,
        _request: Request<ListRuleRequest>,
    ) -> Result<Response<ListRuleResponse>, Status> {
        Err(unimplemented("ListRule"))
    }
}
