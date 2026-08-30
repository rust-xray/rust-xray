//! gRPC server reflection with Xray-compatible service listing.

use prost::Message;
use prost_types::FileDescriptorSet;
use tonic_reflection::server::Builder;

use crate::api::legacy_alias::{
    CANONICAL_HANDLER_SERVICE, CANONICAL_LOGGER_SERVICE, CANONICAL_OBSERVATORY_SERVICE,
    CANONICAL_ROUTING_SERVICE, CANONICAL_STATS_SERVICE, LEGACY_HANDLER_SERVICE,
    LEGACY_LOGGER_SERVICE, LEGACY_ROUTING_SERVICE, LEGACY_STATS_SERVICE,
};
use crate::api::proto::FILE_DESCRIPTOR_SET;
use crate::api::server::ApiService;

const REFLECTION_V1: &str = "grpc.reflection.v1.ServerReflection";
const REFLECTION_V1ALPHA: &str = "grpc.reflection.v1alpha.ServerReflection";

fn reflection_builder(enabled: &[ApiService]) -> Builder<'_> {
    let mut builder =
        Builder::configure().register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET);
    for name in reflection_list_service_names(enabled) {
        builder = builder.with_service_name(name);
    }
    builder
}

/// Build reflection v1 with canonical descriptor symbols and explicit service listing.
pub fn build_api_reflection_v1(
    enabled: &[ApiService],
) -> Result<
    tonic_reflection::server::v1::ServerReflectionServer<
        impl tonic_reflection::server::v1::ServerReflection,
    >,
    tonic_reflection::server::Error,
> {
    reflection_builder(enabled).build_v1()
}

/// Build reflection v1alpha with the same service list as v1 (grpc-go `reflection.Register` parity).
pub fn build_api_reflection_v1alpha(
    enabled: &[ApiService],
) -> Result<
    tonic_reflection::server::v1alpha::ServerReflectionServer<
        impl tonic_reflection::server::v1alpha::ServerReflection,
    >,
    tonic_reflection::server::Error,
> {
    reflection_builder(enabled).build_v1alpha()
}

fn reflection_list_service_names(enabled: &[ApiService]) -> Vec<String> {
    let mut names = Vec::new();
    for service in enabled {
        match service {
            ApiService::Reflection => {
                names.push(REFLECTION_V1.to_string());
                names.push(REFLECTION_V1ALPHA.to_string());
            }
            ApiService::Handler => {
                names.push(CANONICAL_HANDLER_SERVICE.to_string());
                names.push(LEGACY_HANDLER_SERVICE.to_string());
            }
            ApiService::Stats => {
                names.push(CANONICAL_STATS_SERVICE.to_string());
                names.push(LEGACY_STATS_SERVICE.to_string());
            }
            ApiService::Routing => {
                names.push(CANONICAL_ROUTING_SERVICE.to_string());
                names.push(LEGACY_ROUTING_SERVICE.to_string());
            }
            ApiService::Logger => {
                names.push(CANONICAL_LOGGER_SERVICE.to_string());
                names.push(LEGACY_LOGGER_SERVICE.to_string());
            }
            ApiService::Observatory => {
                names.push(CANONICAL_OBSERVATORY_SERVICE.to_string());
            }
        }
    }
    names
}

/// Returns true if the descriptor set contains any legacy `v2ray.core` API service symbol.
pub fn descriptor_set_contains_legacy_api_symbols() -> bool {
    let Ok(set) = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET) else {
        return false;
    };
    set.file.iter().any(|file| {
        file.package
            .as_deref()
            .is_some_and(|package| package.starts_with("v2ray.core"))
    })
}
