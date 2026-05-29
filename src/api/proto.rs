//! Generated Xray-compatible gRPC types (`tonic_build` from `proto/`).

pub mod common {
    pub mod net {
        tonic::include_proto!("xray.common.net");
    }
    pub mod protocol {
        tonic::include_proto!("xray.common.protocol");
    }
    pub mod serial {
        tonic::include_proto!("xray.common.serial");
    }
}

pub mod core {
    tonic::include_proto!("xray.core");
}

pub mod proxy {
    pub mod vless {
        tonic::include_proto!("xray.proxy.vless");
    }
}

pub mod app {
    pub mod log {
        pub mod command {
            tonic::include_proto!("xray.app.log.command");
        }
    }
    pub mod proxyman {
        pub mod command {
            tonic::include_proto!("xray.app.proxyman.command");
        }
    }
    pub mod router {
        pub mod command {
            tonic::include_proto!("xray.app.router.command");
        }
    }
    pub mod stats {
        pub mod command {
            tonic::include_proto!("xray.app.stats.command");
        }
    }
}

pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("xray_api_descriptor");
