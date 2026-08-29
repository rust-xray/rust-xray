use std::sync::Arc;

use tonic::{Code, Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, log_rpc_ok, rpc_remote_addr};
use crate::api::proto::app::log::command::{
    logger_service_server::LoggerService, RestartLoggerRequest, RestartLoggerResponse,
};
use crate::logging::{LoggerRestartError, RuntimeLoggerController};

const SERVICE: &str = "LoggerService";

#[derive(Debug, Clone)]
pub struct LoggerServiceImpl {
    controller: Arc<RuntimeLoggerController>,
}

impl LoggerServiceImpl {
    pub fn new(controller: Arc<RuntimeLoggerController>) -> Self {
        Self { controller }
    }

    pub fn from_global() -> Result<Self, Box<Status>> {
        RuntimeLoggerController::global()
            .map(Self::new)
            .ok_or_else(|| Box::new(Status::new(Code::Internal, "unable to get logger instance")))
    }
}

impl Default for LoggerServiceImpl {
    fn default() -> Self {
        Self::from_global().expect("LoggerService requires RuntimeLoggerController")
    }
}

fn map_restart_error(err: LoggerRestartError) -> Status {
    match err {
        LoggerRestartError::Unavailable => {
            Status::new(Code::Internal, "unable to get logger instance")
        }
        LoggerRestartError::CloseFailed(message) => {
            Status::new(Code::Internal, format!("failed to close logger: {message}"))
        }
        LoggerRestartError::StartFailed(message) => {
            Status::new(Code::Internal, format!("failed to start logger: {message}"))
        }
    }
}

#[tonic::async_trait]
impl LoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RestartLogger", &remote);
        let _request = request.into_inner();

        match self.controller.restart() {
            Ok(()) => {
                log_rpc_ok(SERVICE, "RestartLogger", &remote, "ok");
                Ok(Response::new(RestartLoggerResponse {}))
            }
            Err(err) => {
                log_rpc_err(SERVICE, "RestartLogger", &remote, &err.to_string());
                Err(map_restart_error(err))
            }
        }
    }
}
