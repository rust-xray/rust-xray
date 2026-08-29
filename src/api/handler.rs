use std::sync::Arc;

use prost::Message;
use tonic::{Code, Request, Response, Status};

use crate::api::diagnostics::{log_rpc_call, log_rpc_err, log_rpc_ok, rpc_remote_addr};
use crate::api::proto::app::proxyman::command::{
    handler_service_server::HandlerService, AddInboundRequest, AddInboundResponse,
    AddOutboundRequest, AddOutboundResponse, AddUserOperation, AlterInboundRequest,
    AlterInboundResponse, AlterOutboundRequest, AlterOutboundResponse, GetInboundUserRequest,
    GetInboundUserResponse, GetInboundUsersCountResponse, ListInboundsRequest,
    ListInboundsResponse, ListOutboundsRequest, ListOutboundsResponse, RemoveInboundRequest,
    RemoveInboundResponse, RemoveOutboundRequest, RemoveOutboundResponse, RemoveUserOperation,
};
use crate::api::proto::common::protocol::User;
use crate::api::proto::common::serial::TypedMessage;
use crate::api::proto::proxy::vless::Account;
use crate::runtime::{HandlerRuntime, InboundManagerError, OutboundManagerError};
use crate::vless::user_manager::{managed_user_from_vless_account, ManagedUser, UserManagerError};

const SERVICE: &str = "HandlerService";

const ADD_USER_OPERATION_TYPE: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER_OPERATION_TYPE: &str = "xray.app.proxyman.command.RemoveUserOperation";
const VLESS_ACCOUNT_TYPE: &str = "xray.proxy.vless.Account";

pub struct HandlerServiceImpl {
    runtime: Arc<HandlerRuntime>,
}

impl HandlerServiceImpl {
    pub fn new(runtime: Arc<HandlerRuntime>) -> Self {
        Self { runtime }
    }
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

fn map_inbound_manager_error(err: InboundManagerError) -> Status {
    match err {
        InboundManagerError::AlreadyExists { tag } => {
            Status::already_exists(format!("inbound tag already exists: {tag}"))
        }
        InboundManagerError::NotFound { tag } => {
            Status::new(Code::NotFound, format!("inbound tag not found: {tag}"))
        }
        InboundManagerError::Protected { tag } => Status::new(
            Code::FailedPrecondition,
            format!("inbound tag is protected from HandlerService removal: {tag}"),
        ),
        InboundManagerError::BindFailed { message } => Status::new(Code::Unavailable, message),
        InboundManagerError::InvalidConfig { message } => {
            Status::new(Code::InvalidArgument, message)
        }
        InboundManagerError::Unsupported { message } => Status::new(Code::InvalidArgument, message),
        InboundManagerError::Internal { message } => Status::new(Code::Internal, message),
    }
}

fn map_outbound_manager_error(err: OutboundManagerError) -> Status {
    match err {
        OutboundManagerError::AlreadyExists { tag } => {
            Status::already_exists(format!("outbound tag already exists: {tag}"))
        }
        OutboundManagerError::NotFound { tag } => {
            Status::new(Code::NotFound, format!("outbound tag not found: {tag}"))
        }
        OutboundManagerError::InvalidConfig { message } => {
            Status::new(Code::InvalidArgument, message)
        }
        OutboundManagerError::Unsupported { message } => {
            Status::new(Code::InvalidArgument, message)
        }
    }
}

fn inbound_not_found(tag: &str) -> Status {
    Status::new(Code::NotFound, format!("inbound tag not found: {tag}"))
}

fn require_inbound_tag(tag: &str) -> Result<&str, Status> {
    if tag.trim().is_empty() {
        return Err(Status::new(
            Code::InvalidArgument,
            "inbound tag is required",
        ));
    }
    Ok(tag)
}

fn managed_user_to_proto(user: &ManagedUser) -> Result<User, Status> {
    if user.email.is_empty() {
        return Err(Status::new(
            Code::InvalidArgument,
            "vless user email is required for HandlerService introspection",
        ));
    }

    let account = Account {
        id: user.id.to_string(),
        flow: user.flow.clone().unwrap_or_default(),
        encryption: "none".to_string(),
        seconds: user.expiry_secs.unwrap_or(0),
        ..Default::default()
    };
    let account_msg = TypedMessage {
        r#type: "xray.proxy.vless.Account".to_string(),
        value: account.encode_to_vec(),
    };

    Ok(User {
        level: user.level.unwrap_or(0),
        email: user.email.clone(),
        account: Some(account_msg),
    })
}

fn listable_managed_users(
    manager: &crate::vless::user_manager::VlessUserManager,
) -> Vec<ManagedUser> {
    manager
        .list_managed_users()
        .into_iter()
        .filter(|user| !user.email.is_empty())
        .collect()
}

fn unsupported_account_type(account_type: &str) -> Status {
    Status::unimplemented(format!(
        "account type is not supported in rust-xray: {account_type}"
    ))
}

fn validate_vless_account_encryption(encryption: &str) -> Result<(), Status> {
    let value = encryption.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        Ok(())
    } else {
        Err(Status::new(
            Code::InvalidArgument,
            format!("unsupported vless account encryption: {encryption}"),
        ))
    }
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

    let account_type = account.r#type.trim();
    let account_type_lower = account_type.to_ascii_lowercase();
    if account_type != VLESS_ACCOUNT_TYPE {
        if account_type_lower.contains("vmess")
            || account_type_lower.contains("trojan")
            || account_type_lower.contains("shadowsocks")
            || account_type_lower.contains("socks")
            || account_type_lower.contains("http")
            || account_type_lower.contains("wireguard")
            || account_type_lower.contains("hysteria")
        {
            return Err(unsupported_account_type(account_type));
        }
        return Err(unsupported_account_type(account_type));
    }

    let vless_account = crate::api::proto::proxy::vless::Account::decode(account.value.as_slice())
        .map_err(|err| {
            Status::new(
                Code::InvalidArgument,
                format!("failed to decode xray.proxy.vless.Account: {err}"),
            )
        })?;

    validate_vless_account_encryption(&vless_account.encryption)?;

    let level = Some(user.level);

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
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AddInbound", &remote);
        let inbound = request
            .into_inner()
            .inbound
            .ok_or_else(|| Status::new(Code::InvalidArgument, "inbound is required"))?;
        self.runtime
            .inbound
            .add_inbound(inbound)
            .await
            .map_err(map_inbound_manager_error)?;
        log_rpc_ok(SERVICE, "AddInbound", &remote, "ok");
        Ok(Response::new(AddInboundResponse {}))
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RemoveInbound", &remote);
        let tag = request.into_inner().tag;
        self.runtime
            .inbound
            .remove_inbound(&tag)
            .await
            .map_err(map_inbound_manager_error)?;
        log_rpc_ok(SERVICE, "RemoveInbound", &remote, &format!("tag={tag}"));
        Ok(Response::new(RemoveInboundResponse {}))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AlterInbound", &remote);
        let request = request.into_inner();
        let manager = self
            .runtime
            .inbound
            .user_managers()
            .get(&request.tag)
            .map_err(|err| Status::new(Code::NotFound, err.to_string()))?;

        let operation = request
            .operation
            .ok_or_else(|| Status::new(Code::InvalidArgument, "operation is required"))?;

        let operation_type = operation.r#type.trim();
        if operation_type == ADD_USER_OPERATION_TYPE {
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
            if let Some(config) = self.runtime.inbound.listener_config_for_tag(&request.tag) {
                config
                    .auth
                    .auth_set()
                    .reject_duplicate_user_id(managed.id, &request.tag)
                    .map_err(|err| Status::new(Code::InvalidArgument, err.to_string()))?;
            }
            manager.add_user(managed).map_err(map_user_manager_error)?;
            log_rpc_ok(SERVICE, "AlterInbound", &remote, "AddUserOperation");
            return Ok(Response::new(AlterInboundResponse {}));
        }

        if operation_type == REMOVE_USER_OPERATION_TYPE {
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
            log_rpc_ok(SERVICE, "AlterInbound", &remote, "RemoveUserOperation");
            return Ok(Response::new(AlterInboundResponse {}));
        }

        log_rpc_err(
            SERVICE,
            "AlterInbound",
            &remote,
            &format!("unsupported operation type: {operation_type}"),
        );
        Err(Status::new(
            Code::InvalidArgument,
            format!("unsupported inbound operation type: {operation_type}"),
        ))
    }

    async fn list_inbounds(
        &self,
        request: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "ListInbounds", &remote);
        let request = request.into_inner();
        let inbounds = self
            .runtime
            .inbound
            .list_inbounds(request.is_only_tags)
            .map_err(map_inbound_manager_error)?;

        log_rpc_ok(
            SERVICE,
            "ListInbounds",
            &remote,
            &format!("count={}", inbounds.len()),
        );
        Ok(Response::new(ListInboundsResponse { inbounds }))
    }

    async fn get_inbound_users(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "GetInboundUsers", &remote);
        let request = request.into_inner();
        let tag = require_inbound_tag(&request.tag)?;
        let manager = self
            .runtime
            .inbound
            .user_managers()
            .get(tag)
            .map_err(|_| inbound_not_found(tag))?;

        let managed = if request.email.trim().is_empty() {
            listable_managed_users(&manager)
        } else {
            let email = request.email.trim();
            let user = manager.get_managed_user_by_email(email).ok_or_else(|| {
                Status::new(Code::NotFound, format!("vless user not found: {email}"))
            })?;
            vec![user]
        };

        let users = managed
            .iter()
            .map(managed_user_to_proto)
            .collect::<Result<Vec<_>, _>>()?;

        log_rpc_ok(
            SERVICE,
            "GetInboundUsers",
            &remote,
            &format!("count={}", users.len()),
        );
        Ok(Response::new(GetInboundUserResponse { users }))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        let request = request.into_inner();
        let tag = require_inbound_tag(&request.tag)?;
        let manager = self
            .runtime
            .inbound
            .user_managers()
            .get(tag)
            .map_err(|_| inbound_not_found(tag))?;

        let count = if request.email.trim().is_empty() {
            i64::try_from(manager.user_count())
                .map_err(|_| Status::new(Code::Internal, "inbound user count exceeds i64::MAX"))?
        } else {
            let email = request.email.trim();
            if manager.get_managed_user_by_email(email).is_some() {
                1
            } else {
                0
            }
        };

        Ok(Response::new(GetInboundUsersCountResponse { count }))
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AddOutbound", &remote);
        let outbound = request
            .into_inner()
            .outbound
            .ok_or_else(|| Status::new(Code::InvalidArgument, "outbound is required"))?;
        self.runtime
            .outbound
            .add_outbound(outbound)
            .map_err(map_outbound_manager_error)?;
        log_rpc_ok(SERVICE, "AddOutbound", &remote, "ok");
        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "RemoveOutbound", &remote);
        let tag = request.into_inner().tag;
        self.runtime
            .outbound
            .remove_outbound(&tag)
            .map_err(map_outbound_manager_error)?;
        log_rpc_ok(SERVICE, "RemoveOutbound", &remote, &format!("tag={tag}"));
        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "AlterOutbound", &remote);
        let request = request.into_inner();
        let _tag = request.tag;
        let operation = request
            .operation
            .ok_or_else(|| Status::new(Code::InvalidArgument, "operation is required"))?;
        log_rpc_err(
            SERVICE,
            "AlterOutbound",
            &remote,
            &format!("unsupported operation type: {}", operation.r#type),
        );
        Err(Status::new(
            Code::InvalidArgument,
            format!("not an outbound operation: {}", operation.r#type),
        ))
    }

    async fn list_outbounds(
        &self,
        request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        let remote = rpc_remote_addr(&request);
        log_rpc_call(SERVICE, "ListOutbounds", &remote);
        let _request = request.into_inner();
        let outbounds = self.runtime.outbound.list_outbounds();
        log_rpc_ok(
            SERVICE,
            "ListOutbounds",
            &remote,
            &format!("count={}", outbounds.len()),
        );
        Ok(Response::new(ListOutboundsResponse { outbounds }))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/api/handler.rs"]
mod tests;
