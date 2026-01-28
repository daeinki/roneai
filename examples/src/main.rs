use roneai_mcp_server::{
    oneai_mcp_server_add_prompt, oneai_mcp_server_add_resource,
    oneai_mcp_server_add_resource_template, oneai_mcp_server_add_tool,
    oneai_mcp_server_add_transport, oneai_mcp_server_create, oneai_mcp_server_run,
    oneai_mcp_server_stop, OneaiEventListener, OneaiMcpServerConfigInfo,
    OneaiTransportType, ONEAI_ERROR_OK,
};
use tokio::signal;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::init();

    // 1) Create server with optional capability path
    let server = oneai_mcp_server_create(Some(OneaiMcpServerConfigInfo {
        capability_path: Some("/opt/oneai/capabilities".to_string()),
    }));

    // 2) Register transports (stdio shown as default)
    let rc = oneai_mcp_server_add_transport(
        &server,
        OneaiTransportType::StreamableHttp,
        "127.0.0.1",
        8080,
        Some(OneaiEventListener {
            on_connected: Some(|users| println!("[event] connected users: {users}")),
            on_disconnected: Some(|users| println!("[event] disconnected users: {users}")),
        }),
    );
    assert_eq!(rc, ONEAI_ERROR_OK, "failed to add transport");

    // 3) Register capabilities
    assert_eq!(oneai_mcp_server_add_tool(&server, "echo"), ONEAI_ERROR_OK);
    assert_eq!(oneai_mcp_server_add_resource(&server, "fs"), ONEAI_ERROR_OK);
    assert_eq!(oneai_mcp_server_add_resource_template(&server, "template:fs"), ONEAI_ERROR_OK);
    assert_eq!(oneai_mcp_server_add_prompt(&server, "hello"), ONEAI_ERROR_OK);

    // 4) Start server (facade); this call is non-blocking in this simplified example
    let rc = oneai_mcp_server_run(&server);
    assert_eq!(rc, ONEAI_ERROR_OK, "failed to start server");

    println!("roneai MCP server running. Press Ctrl+C to stop.");
    // Keep alive until Ctrl+C
    signal::ctrl_c().await.expect("failed to listen for ctrl_c");

    let rc = oneai_mcp_server_stop(&server);
    assert_eq!(rc, ONEAI_ERROR_OK, "failed to stop server");
    println!("roneai MCP server stopped.");
}
