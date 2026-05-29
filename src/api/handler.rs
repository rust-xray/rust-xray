use std::sync::Arc;

use prost::Message;
use tonic::{Code, Request, Response, Status};

use crate::api::proto::app::proxyman::command::{
    handler_service_server::HandlerService, AddInboundRequest, AddInboundResponse,
    AddOutboundRequest, AddOutboundResponse, AddUserOperation, AlterInboundRequest,
    AlterInboundResponse, AlterOutboundRequest, AlterOutboundResponse, GetInboundUserRequest,
    GetInboundUserResponse, GetInboundUsersCountResponse, ListInboundsRequest,
    ListInboundsResponse, ListOutboundsRequest, ListOutboundsResponse, RemoveInboundRequest,
    RemoveInboundResponse, RemoveOutboundRequest, RemoveOutboundResponse, RemoveUserOperation,
};
use crate::runtime::InboundUserManagers;
use crate::vless::user_manager::{managed_user_from_vless_account, UserManagerError};

#[derive(Debug)]
pub struct HandlerServiceImpl {
    managers: Arc<InboundUserManagers>,
}

impl HandlerServiceImpl {
    pub fn new(managers: Arc<InboundUserManagers>) -> Self {
        Self { managers }
    }
}

fn unimplemented(method: &str) -> Status {
    Status::unimplemented(format!(
        "HandlerService.{method} is not implemented in rust-xray"
    ))
}

fn map_user_manager_error(err: UserManagerError) -> Status {
    match err {
        UserManagerError::DuplicateUuid { id } => {
            Status::already_exists(format!("duplicate vless user id: {id}"))
        }
        UserManagerError::DuplicateEmail { email } => {
            Status::already_exists(format!("duplicate vless user email: {email}"))
        }
        UserManagerError::UserNotFound { email } => {
            Status::new(Code::NotFound, format!("vless user not found: {email}"))
        }
        UserManagerError::InvalidUser(message) => Status::new(Code::InvalidArgument, message),
    }
}

fn unsupported_account_type(account_type: &str) -> Status {
    Status::unimplemented(format!(
        "account type is not supported in rust-xray: {account_type}"
    ))
}

fn parse_vless_user_from_proto(
    user: crate::api::proto::common::protocol::User,
) -> Result<crate::vless::user_manager::ManagedUser, Status> {
    let email = user.email;
    if email.trim().is_empty() {
        return Err(Status::new(
            Code::InvalidArgument,
            "user email is required for VLESS AddUser",
        ));
    }

    let account = user
        .account
        .ok_or_else(|| Status::new(Code::InvalidArgument, "user account is required"))?;

    let account_type = account.r#type;
    let account_type_lower = account_type.to_ascii_lowercase();
    if !(account_type_lower.contains("vless") && account_type_lower.contains("account")) {
        if account_type_lower.contains("vmess")
            || account_type_lower.contains("trojan")
            || account_type_lower.contains("shadowsocks")
            || account_type_lower.contains("socks")
            || account_type_lower.contains("http")
        {
            return Err(unsupported_account_type(&account_type));
        }
        return Err(unsupported_account_type(&account_type));
    }

    let vless_account = crate::api::proto::proxy::vless::Account::decode(account.value.as_slice())
        .map_err(|err| {
            Status::new(
                Code::InvalidArgument,
                format!("failed to decode xray.proxy.vless.Account: {err}"),
            )
        })?;

    let level = if user.level == 0 {
        None
    } else {
        Some(user.level)
    };

    managed_user_from_vless_account(
        email,
        level,
        &vless_account.id,
        &vless_account.flow,
        vless_account.seconds,
    )
    .map_err(map_user_manager_error)
}

#[tonic::async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_inbound(
        &self,
        _request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        Err(unimplemented("AddInbound"))
    }

    async fn remove_inbound(
        &self,
        _request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        Err(unimplemented("RemoveInbound"))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let request = request.into_inner();
        let manager = self
            .managers
            .get(&request.tag)
            .map_err(|err| Status::new(Code::NotFound, err.to_string()))?;

        let operation = request
            .operation
            .ok_or_else(|| Status::new(Code::InvalidArgument, "operation is required"))?;

        let operation_type = operation.r#type;
        if operation_type.contains("AddUserOperation") {
            let add = AddUserOperation::decode(operation.value.as_slice()).map_err(|err| {
                Status::new(
                    Code::InvalidArgument,
                    format!("failed to decode AddUserOperation: {err}"),
                )
            })?;
            let user = add
                .user
                .ok_or_else(|| Status::new(Code::InvalidArgument, "user is required"))?;
            let managed = parse_vless_user_from_proto(user)?;
            manager.add_user(managed).map_err(map_user_manager_error)?;
            return Ok(Response::new(AlterInboundResponse {}));
        }

        if operation_type.contains("RemoveUserOperation") {
            let remove =
                RemoveUserOperation::decode(operation.value.as_slice()).map_err(|err| {
                    Status::new(
                        Code::InvalidArgument,
                        format!("failed to decode RemoveUserOperation: {err}"),
                    )
                })?;
            if remove.email.trim().is_empty() {
                return Err(Status::new(
                    Code::InvalidArgument,
                    "remove user email is required",
                ));
            }
            manager
                .remove_user_by_email(&remove.email)
                .map_err(map_user_manager_error)?;
            return Ok(Response::new(AlterInboundResponse {}));
        }

        Err(Status::new(
            Code::InvalidArgument,
            format!("unsupported inbound operation type: {operation_type}"),
        ))
    }

    async fn list_inbounds(
        &self,
        _request: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        Err(unimplemented("ListInbounds"))
    }

    async fn get_inbound_users(
        &self,
        _request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        Err(unimplemented("GetInboundUsers"))
    }

    async fn get_inbound_users_count(
        &self,
        _request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        Err(unimplemented("GetInboundUsersCount"))
    }

    async fn add_outbound(
        &self,
        _request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        Err(unimplemented("AddOutbound"))
    }

    async fn remove_outbound(
        &self,
        _request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        Err(unimplemented("RemoveOutbound"))
    }

    async fn alter_outbound(
        &self,
        _request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        Err(unimplemented("AlterOutbound"))
    }

    async fn list_outbounds(
        &self,
        _request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        Err(unimplemented("ListOutbounds"))
    }
}
