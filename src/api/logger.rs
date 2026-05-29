use tonic::{Request, Response, Status};

use crate::api::proto::app::log::command::{
    logger_service_server::LoggerService, RestartLoggerRequest, RestartLoggerResponse,
};

#[derive(Debug, Default)]
pub struct LoggerServiceImpl;

#[tonic::async_trait]
impl LoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        _request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        Err(Status::unimplemented(
            "LoggerService.RestartLogger is not implemented in rust-xray",
        ))
    }
}
