use tonic::{Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, rpc_remote_addr};
use crate::api::proto::app::log::command::{
    logger_service_server::LoggerService, RestartLoggerRequest, RestartLoggerResponse,
};

const SERVICE: &str = "LoggerService";

#[derive(Debug, Default)]
pub struct LoggerServiceImpl;

#[tonic::async_trait]
impl LoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RestartLogger", &remote);
        log_rpc_err(SERVICE, "RestartLogger", &remote, "UNIMPLEMENTED");
        Err(Status::unimplemented(
            "LoggerService.RestartLogger is not implemented in rust-xray",
        ))
    }
}
