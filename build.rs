fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "proto";
    let protos = [
        "app/stats/command/command.proto",
        "app/proxyman/command/command.proto",
        "app/log/command/config.proto",
        "app/router/command/command.proto",
        "common/protocol/user.proto",
        "common/serial/typed_message.proto",
        "common/net/network.proto",
        "core/config.proto",
        "proxy/vless/account_minimal.proto",
    ];

    let mut config = tonic_build::configure()
        .build_server(true)
        .build_client(true);

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    config = config.file_descriptor_set_path(out_dir.join("xray_api_descriptor.bin"));

    config.compile_protos(
        &protos
            .iter()
            .map(|p| format!("{proto_root}/{p}"))
            .collect::<Vec<_>>(),
        &[proto_root],
    )?;

    println!("cargo:rerun-if-changed={proto_root}");
    for proto in protos {
        println!("cargo:rerun-if-changed={proto_root}/{proto}");
    }

    Ok(())
}
