use super::*;
use prost::Message;

use crate::api::handler::HandlerServiceImpl;
use crate::api::proto::app::proxyman::command::handler_service_server::HandlerService;
use crate::api::proto::app::proxyman::command::{
    AddUserOperation, AlterInboundRequest, RemoveUserOperation,
};
use crate::api::proto::common::protocol::User;
use crate::api::proto::common::serial::TypedMessage;
use crate::api::proto::proxy::vless::Account;
use crate::runtime::HandlerRuntime;
use crate::vless::user_manager::VlessUserManager;
use std::sync::Arc;
use tonic::Code;

fn handler() -> HandlerServiceImpl {
    let runtime = HandlerRuntime::for_handler_tests(Arc::new(crate::stats::StatsRegistry::new()));
    runtime
        .inbound
        .user_managers()
        .register(Arc::new(VlessUserManager::new("in", vec![])));
    HandlerServiceImpl::new(runtime)
}

fn vless_user_proto(email: &str, id: &str, flow: &str, level: u32, encryption: &str) -> User {
    let account = Account {
        id: id.to_string(),
        flow: flow.to_string(),
        encryption: encryption.to_string(),
        ..Default::default()
    };
    User {
        level,
        email: email.to_string(),
        account: Some(TypedMessage {
            r#type: "xray.proxy.vless.Account".to_string(),
            value: account.encode_to_vec(),
        }),
    }
}

#[test]
fn rejects_unknown_operation_type() {
    let handler = handler();
    let request = AlterInboundRequest {
        tag: "in".to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.NoSuchOperation".to_string(),
            value: vec![],
        }),
    };
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(handler.alter_inbound(tonic::Request::new(request)))
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn rejects_malformed_add_user_payload() {
    let handler = handler();
    let request = AlterInboundRequest {
        tag: "in".to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
            value: vec![0xff, 0xff],
        }),
    };
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(handler.alter_inbound(tonic::Request::new(request)))
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn rejects_unsupported_vless_encryption() {
    let add = AddUserOperation {
        user: Some(vless_user_proto(
            "user@example.com",
            "11111111-1111-1111-1111-111111111111",
            "",
            0,
            "mlkem768x25519plus",
        )),
    };
    let request = AlterInboundRequest {
        tag: "in".to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
            value: add.encode_to_vec(),
        }),
    };
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(handler().alter_inbound(tonic::Request::new(request)))
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn accepts_remna_style_vless_account_with_encryption_none() {
    let handler = handler();
    let add = AddUserOperation {
        user: Some(vless_user_proto(
            "remna@example.com",
            "22222222-2222-2222-2222-222222222222",
            "xtls-rprx-vision",
            0,
            "none",
        )),
    };
    let request = AlterInboundRequest {
        tag: "in".to_string(),
        operation: Some(TypedMessage {
            r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
            value: add.encode_to_vec(),
        }),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(handler.alter_inbound(tonic::Request::new(request)))
        .expect("add user");
}

#[test]
fn remove_user_operation_decodes_by_exact_type() {
    let handler = handler();
    let add = AddUserOperation {
        user: Some(vless_user_proto(
            "remove-me@example.com",
            "33333333-3333-3333-3333-333333333333",
            "",
            0,
            "none",
        )),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(
            handler.alter_inbound(tonic::Request::new(AlterInboundRequest {
                tag: "in".to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                    value: add.encode_to_vec(),
                }),
            })),
        )
        .expect("add");

    let remove = RemoveUserOperation {
        email: "remove-me@example.com".to_string(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(
            handler.alter_inbound(tonic::Request::new(AlterInboundRequest {
                tag: "in".to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.RemoveUserOperation".to_string(),
                    value: remove.encode_to_vec(),
                }),
            })),
        )
        .expect("remove");
}
