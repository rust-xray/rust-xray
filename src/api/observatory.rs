use std::sync::Arc;

use tonic::{Code, Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_ok, rpc_remote_addr};
use crate::api::proto::app::observatory::command::{
    observatory_service_server::ObservatoryService, GetOutboundStatusRequest,
    GetOutboundStatusResponse,
};
use crate::runtime::HandlerRuntime;

const SERVICE: &str = "ObservatoryService";

#[derive(Clone)]
pub struct ObservatoryServiceImpl {
    runtime: Arc<HandlerRuntime>,
}

impl ObservatoryServiceImpl {
    pub fn new(runtime: Arc<HandlerRuntime>) -> Result<Self, Box<Status>> {
        if runtime.observatory.is_none() {
            return Err(Box::new(Status::new(
                Code::FailedPrecondition,
                "unable to get observatory instance",
            )));
        }
        Ok(Self { runtime })
    }
}

#[tonic::async_trait]
impl ObservatoryService for ObservatoryServiceImpl {
    async fn get_outbound_status(
        &self,
        request: Request<GetOutboundStatusRequest>,
    ) -> Result<Response<GetOutboundStatusResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetOutboundStatus", &remote);
        let _request = request.into_inner();

        let observatory = self.runtime.observatory.as_ref().ok_or_else(|| {
            Status::new(
                Code::FailedPrecondition,
                "unable to get observatory instance",
            )
        })?;
        let status = observatory.observation_result();
        log_rpc_ok(SERVICE, "GetOutboundStatus", &remote, "ok");
        Ok(Response::new(GetOutboundStatusResponse {
            status: Some(status),
        }))
    }
}
