use std::sync::Arc;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, rpc_remote_addr};
use crate::api::proto::app::router::command::{
    routing_service_server::RoutingService, AddRuleRequest, AddRuleResponse,
    GetBalancerInfoRequest, GetBalancerInfoResponse, ListRuleItem, ListRuleRequest,
    ListRuleResponse, OverrideBalancerTargetRequest, OverrideBalancerTargetResponse, OverrideInfo,
    PrincipleTargetInfo, RemoveRuleRequest, RemoveRuleResponse, RoutingContext,
    SubscribeRoutingStatsRequest, TestRouteRequest,
};
use crate::routing::RouteError;
use crate::routing::{apply_field_selectors, route_context_from_proto, RuntimeRouter};
use crate::runtime::HandlerRuntime;

const SERVICE: &str = "RoutingService";

pub struct RoutingServiceImpl {
    router: Arc<RuntimeRouter>,
}

impl RoutingServiceImpl {
    pub fn new(handler_runtime: Arc<HandlerRuntime>) -> Self {
        Self {
            router: Arc::clone(&handler_runtime.router),
        }
    }
}

fn map_route_error(err: RouteError) -> Status {
    match err {
        RouteError::NoClue => Status::internal("no clue"),
        RouteError::InvalidArgument(message) | RouteError::UnsupportedRule(message) => {
            Status::invalid_argument(message)
        }
        RouteError::DuplicateRuleTag(tag) => {
            Status::invalid_argument(format!("duplicate ruleTag {tag}"))
        }
        RouteError::DuplicateBalancerTag(_) => Status::invalid_argument("duplicate balancer tag"),
        RouteError::BalancerNotFound(tag) => Status::not_found(format!("cannot find tag {tag}")),
        RouteError::Balancer(message) => Status::internal(message),
        RouteError::UnresolvedDependencies(message) => Status::invalid_argument(message),
    }
}

#[tonic::async_trait]
impl RoutingService for RoutingServiceImpl {
    type SubscribeRoutingStatsStream = ReceiverStream<Result<RoutingContext, Status>>;

    async fn subscribe_routing_stats(
        &self,
        request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "SubscribeRoutingStats", &remote);
        let stats = self.router.routing_stats().ok_or_else(|| {
            log_rpc_err(
                SERVICE,
                "SubscribeRoutingStats",
                &remote,
                "routing stats disabled",
            );
            Status::internal("Routing statistics not enabled.")
        })?;
        let selectors = request.into_inner().field_selectors;
        let mut receiver = stats.subscribe();
        let (tx, rx) = tokio::sync::mpsc::channel(ROUTING_STATS_CAPACITY);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    received = receiver.recv() => {
                        match received {
                            Ok(decision) => {
                                let payload = apply_field_selectors(&decision, &selectors);
                                if tx.send(Ok(payload)).await.is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
            stats.unsubscribe();
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn test_route(
        &self,
        request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "TestRoute", &remote);
        let req = request.into_inner();
        let Some(ctx_proto) = req.routing_context else {
            log_rpc_err(SERVICE, "TestRoute", &remote, "missing routing context");
            return Err(Status::invalid_argument("Invalid routing request."));
        };
        let ctx = route_context_from_proto(&ctx_proto);
        let decision = self.router.pick_route(ctx).await.map_err(map_route_error)?;
        if req.publish_result {
            if let Some(stats) = self.router.routing_stats() {
                stats.publish(decision.clone());
            }
        }
        Ok(Response::new(apply_field_selectors(
            &decision,
            &req.field_selectors,
        )))
    }

    async fn get_balancer_info(
        &self,
        request: Request<GetBalancerInfoRequest>,
    ) -> Result<Response<GetBalancerInfoResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetBalancerInfo", &remote);
        let tag = request.into_inner().tag;
        let override_target = self
            .router
            .get_balancer_override(&tag)
            .map_err(map_route_error)?;
        let principle = self
            .router
            .get_balancer_principle_targets(&tag)
            .unwrap_or_default();
        Ok(Response::new(GetBalancerInfoResponse {
            balancer: Some(crate::api::proto::app::router::command::BalancerMsg {
                r#override: Some(OverrideInfo {
                    target: override_target,
                }),
                principle_target: Some(PrincipleTargetInfo { tag: principle }),
            }),
        }))
    }

    async fn override_balancer_target(
        &self,
        request: Request<OverrideBalancerTargetRequest>,
    ) -> Result<Response<OverrideBalancerTargetResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "OverrideBalancerTarget", &remote);
        let req = request.into_inner();
        self.router
            .set_balancer_override(&req.balancer_tag, req.target)
            .map_err(map_route_error)?;
        Ok(Response::new(OverrideBalancerTargetResponse {}))
    }

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<AddRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AddRule", &remote);
        let req = request.into_inner();
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("AddRule: config type error"))?;
        self.router
            .add_rule(&config, req.should_append)
            .map_err(map_route_error)?;
        Ok(Response::new(AddRuleResponse {}))
    }

    async fn remove_rule(
        &self,
        request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RemoveRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RemoveRule", &remote);
        self.router
            .remove_rule(&request.into_inner().rule_tag)
            .map_err(map_route_error)?;
        Ok(Response::new(RemoveRuleResponse {}))
    }

    async fn list_rule(
        &self,
        request: Request<ListRuleRequest>,
    ) -> Result<Response<ListRuleResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "ListRule", &remote);
        let _ = request;
        let rules = self
            .router
            .list_rules()
            .into_iter()
            .map(|(tag, rule_tag)| ListRuleItem { tag, rule_tag })
            .collect();
        Ok(Response::new(ListRuleResponse { rules }))
    }
}

const ROUTING_STATS_CAPACITY: usize = 64;
