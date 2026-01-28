/*
 * Copyright (c) 2025 Samsung Electronics Co., Ltd
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust representation of `oneai_mcp_server.h`.
//! This module keeps the API surface close to the original C header while
//! providing a safe Rust-centric façade for embedding in applications.

use log::error;
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder as AutoBuilder, service::TowerToHyperService};
use serde_json;
use rmcp::{
    model::{self, AnnotateAble, CallToolRequestParams, CallToolResult, JsonObject, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams, Prompt, RawContent, RawResource, RawResourceTemplate, Resource, ResourceTemplate, ServerCapabilities, ServerInfo, Tool},
    transport::streamable_http_server::{session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService},
    ServiceExt,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::{runtime::Runtime, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// Error codes mirroring the C API style.
pub const ONEAI_ERROR_OK: i32 = 0;
pub const ONEAI_ERROR_INVALID_ARG: i32 = -1;
pub const ONEAI_ERROR_ALREADY_RUNNING: i32 = -2;
pub const ONEAI_ERROR_NOT_RUNNING: i32 = -3;
pub const ONEAI_ERROR_INTERNAL: i32 = -500;

/// Transport types supported by the façade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum OneaiTransportType {
    Grpc = 0,
    StreamableHttp = 2,
    Stdio = 3,
    Tidl = 4,
}

impl OneaiTransportType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Grpc),
            2 => Some(Self::StreamableHttp),
            3 => Some(Self::Stdio),
            4 => Some(Self::Tidl),
            _ => None,
        }
    }
}

/// Callback signatures for connection events.
pub type OneaiConnectedCb = fn(u32);
pub type OneaiDisconnectedCb = fn(u32);

/// Event listener aggregation.
#[derive(Clone, Copy, Debug, Default)]
pub struct OneaiEventListener {
    pub on_connected: Option<OneaiConnectedCb>,
    pub on_disconnected: Option<OneaiDisconnectedCb>,
}

/// Server configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OneaiMcpServerConfigInfo {
    pub capability_path: Option<String>,
}

/// Internal transport registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    pub transport_type: OneaiTransportType,
    pub server_address: String,
    pub port: i32,
    #[serde(skip)]
    pub event_listener: Option<OneaiEventListener>,
}

/// A lightweight MCP server façade.
#[derive(Clone, Debug)]
pub struct OneaiMcpServer {
    pub config: OneaiMcpServerConfigInfo,
    pub transports: Arc<Mutex<Vec<TransportConfig>>>,
    pub tools: Arc<Mutex<Vec<String>>>,
    pub resources: Arc<Mutex<Vec<String>>>,
    pub resource_templates: Arc<Mutex<Vec<String>>>,
    pub prompts: Arc<Mutex<Vec<String>>>,
    running: Arc<AtomicBool>,
    connected_users: Arc<AtomicU32>,
    runtime: Arc<Mutex<Option<Runtime>>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    cancel_tokens: Arc<Mutex<Vec<CancellationToken>>>,
}

impl Default for OneaiMcpServer {
    fn default() -> Self {
        Self::new(None)
    }
}

impl OneaiMcpServer {
    /// Create a new server instance.
    pub fn new(config: Option<OneaiMcpServerConfigInfo>) -> Self {
        Self {
            config: config.unwrap_or_default(),
            transports: Arc::new(Mutex::new(Vec::new())),
            tools: Arc::new(Mutex::new(Vec::new())),
            resources: Arc::new(Mutex::new(Vec::new())),
            resource_templates: Arc::new(Mutex::new(Vec::new())),
            prompts: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            connected_users: Arc::new(AtomicU32::new(0)),
            runtime: Arc::new(Mutex::new(None)),
            workers: Arc::new(Mutex::new(Vec::new())),
            cancel_tokens: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn add_transport(
        &self,
        transport_type: OneaiTransportType,
        server_address: impl Into<String>,
        port: i32,
        event_listener: Option<OneaiEventListener>,
    ) -> i32 {
        let addr = server_address.into();
        if addr.is_empty() {
            return ONEAI_ERROR_INVALID_ARG;
        }

        // Align validation with Rust SDK expectations:
        // - Streamable HTTP requires a concrete port (>0)
        // - STDIO accepts port 0 (ignored)
        if matches!(transport_type, OneaiTransportType::StreamableHttp) && port <= 0 {
            return ONEAI_ERROR_INVALID_ARG;
        }

        let mut guard = self.transports.lock().unwrap();
        guard.push(TransportConfig {
            transport_type,
            server_address: addr,
            port,
            event_listener,
        });
        ONEAI_ERROR_OK
    }

    pub fn add_tool(&self, tool_name: impl Into<String>) -> i32 {
        let name = tool_name.into();
        if name.is_empty() {
            return ONEAI_ERROR_INVALID_ARG;
        }
        self.tools.lock().unwrap().push(name);
        ONEAI_ERROR_OK
    }

    pub fn add_resource(&self, resource_name: impl Into<String>) -> i32 {
        let name = resource_name.into();
        if name.is_empty() {
            return ONEAI_ERROR_INVALID_ARG;
        }
        self.resources.lock().unwrap().push(name);
        ONEAI_ERROR_OK
    }

    pub fn add_resource_template(&self, resource_template_name: impl Into<String>) -> i32 {
        let name = resource_template_name.into();
        if name.is_empty() {
            return ONEAI_ERROR_INVALID_ARG;
        }
        self.resource_templates.lock().unwrap().push(name);
        ONEAI_ERROR_OK
    }

    pub fn add_prompt(&self, prompt_name: impl Into<String>) -> i32 {
        let name = prompt_name.into();
        if name.is_empty() {
            return ONEAI_ERROR_INVALID_ARG;
        }
        self.prompts.lock().unwrap().push(name);
        ONEAI_ERROR_OK
    }

    /// Start the server; in this façade we simply mark as running and notify listeners.
    pub fn run(&self) -> i32 {
        if self.running.swap(true, Ordering::SeqCst) {
            return ONEAI_ERROR_ALREADY_RUNNING;
        }
        let transports = self.transports.lock().unwrap().clone();
        if transports.is_empty() {
            error!("no transports configured");
            self.running.store(false, Ordering::SeqCst);
            return ONEAI_ERROR_INVALID_ARG;
        }

        let rt = Runtime::new().map_err(|_| ONEAI_ERROR_INTERNAL).unwrap();
        let handler = OneaiServerHandler::new(
            self.tools.clone(),
            self.resources.clone(),
            self.resource_templates.clone(),
            self.prompts.clone(),
        );

        // spawn transports
        for t in transports {
            match t.transport_type {
                OneaiTransportType::StreamableHttp => {
                    let addr: SocketAddr = format!("{}:{}", t.server_address, t.port)
                        .parse()
                        .map_err(|_| ONEAI_ERROR_INVALID_ARG)
                        .unwrap();
                    let handler_factory = handler.clone();
                    let ct_main = CancellationToken::new();
                    let ct = ct_main.clone();
                    let config = StreamableHttpServerConfig {
                        cancellation_token: ct.clone(),
                        ..Default::default()
                    };
                    let session_manager = Arc::new(LocalSessionManager::default());
                    let service = StreamableHttpService::new(
                        move || Ok(handler_factory.clone()),
                        session_manager,
                        config,
                    );
                    let join = rt.spawn(async move {
                        let listener = match tokio::net::TcpListener::bind(addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                error!("failed to bind {addr}: {e}");
                                return;
                            }
                        };
                        let builder = Arc::new(AutoBuilder::new(TokioExecutor::new()));
                        loop {
                            if ct.is_cancelled() {
                                break;
                            }
                            let Ok((stream, _peer)) = listener.accept().await else { continue };
                            let builder = builder.clone();
                            let svc = TowerToHyperService::new(service.clone());
                            tokio::spawn(async move {
                                if let Err(e) = builder
                                    .serve_connection(TokioIo::new(stream), svc)
                                    .await
                                {
                                    error!("HTTP conn error: {e}");
                                }
                            });
                        }
                    });
                    self.workers.lock().unwrap().push(join);
                    self.cancel_tokens.lock().unwrap().push(ct_main);
                }
                OneaiTransportType::Stdio => {
                    // Use rmcp's stdio transport for compatibility
                    let handler_factory = handler.clone();
                    let join = rt.spawn(async move {
                        let transport = rmcp::transport::stdio();
                        let _ = handler_factory
                            .serve(transport)
                            .await
                            .map_err(|e| error!("stdio serve error: {e}"));
                    });
                    self.workers.lock().unwrap().push(join);
                }
                _ => {
                    error!("unsupported transport {:?}", t.transport_type);
                }
            }
        }

        self.notify_connected(0);
        *self.runtime.lock().unwrap() = Some(rt);
        ONEAI_ERROR_OK
    }

    /// Stop the server and notify listeners.
    pub fn stop(&self) -> i32 {
        if !self.running.swap(false, Ordering::SeqCst) {
            return ONEAI_ERROR_NOT_RUNNING;
        }
        // cancel http servers
        for ct in self.cancel_tokens.lock().unwrap().drain(..) {
            ct.cancel();
        }
        // wait for tasks to finish
        if let Some(rt) = self.runtime.lock().unwrap().as_ref() {
            rt.block_on(async {
                let mut workers = self.workers.lock().unwrap();
                while let Some(handle) = workers.pop() {
                    let _ = handle.abort();
                }
            });
        }
        self.notify_disconnected(0);
        ONEAI_ERROR_OK
    }

    fn notify_connected(&self, users: u32) {
        self.connected_users.store(users, Ordering::SeqCst);
        for transport in self.transports.lock().unwrap().iter() {
            if let Some(listener) = transport.event_listener {
                if let Some(cb) = listener.on_connected {
                    cb(users);
                }
            }
        }
    }

    fn notify_disconnected(&self, users: u32) {
        self.connected_users.store(users, Ordering::SeqCst);
        for transport in self.transports.lock().unwrap().iter() {
            if let Some(listener) = transport.event_listener {
                if let Some(cb) = listener.on_disconnected {
                    cb(users);
                }
            }
        }
    }
}

// ---- Convenience free functions mirroring the C-style API ----

pub fn oneai_mcp_server_create(config: Option<OneaiMcpServerConfigInfo>) -> OneaiMcpServer {
    OneaiMcpServer::new(config)
}

pub fn oneai_mcp_server_destroy(_server: OneaiMcpServer) {
    // In Rust, drop is automatic. This function exists for API parity.
}

pub fn oneai_mcp_server_add_transport(
    server: &OneaiMcpServer,
    transport_type: OneaiTransportType,
    server_address: &str,
    port: i32,
    event_listener: Option<OneaiEventListener>,
) -> i32 {
    server.add_transport(transport_type, server_address.to_string(), port, event_listener)
}

pub fn oneai_mcp_server_add_tool(server: &OneaiMcpServer, tool_name: &str) -> i32 {
    server.add_tool(tool_name)
}

pub fn oneai_mcp_server_add_resource(server: &OneaiMcpServer, resource_name: &str) -> i32 {
    server.add_resource(resource_name)
}

pub fn oneai_mcp_server_add_resource_template(
    server: &OneaiMcpServer,
    resource_template_name: &str,
) -> i32 {
    server.add_resource_template(resource_template_name)
}

pub fn oneai_mcp_server_add_prompt(server: &OneaiMcpServer, prompt_name: &str) -> i32 {
    server.add_prompt(prompt_name)
}

pub fn oneai_mcp_server_run(server: &OneaiMcpServer) -> i32 {
    server.run()
}

pub fn oneai_mcp_server_stop(server: &OneaiMcpServer) -> i32 {
    server.stop()
}

// ==== rmcp ServerHandler implementation ====

#[derive(Clone, Debug)]
struct OneaiServerHandler {
    tools: Arc<Mutex<Vec<String>>>,
    resources: Arc<Mutex<Vec<String>>>,
    resource_templates: Arc<Mutex<Vec<String>>>,
    prompts: Arc<Mutex<Vec<String>>>,
}

impl OneaiServerHandler {
    fn new(
        tools: Arc<Mutex<Vec<String>>>,
        resources: Arc<Mutex<Vec<String>>>,
        resource_templates: Arc<Mutex<Vec<String>>>,
        prompts: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            tools,
            resources,
            resource_templates,
            prompts,
        }
    }

    fn tool_models(&self) -> Vec<Tool> {
        self.tools
            .lock()
            .unwrap()
            .iter()
            .map(|name| Tool {
                name: name.clone().into(),
                title: None,
                description: Some(format!("Tool {name}" ).into()),
                input_schema: Arc::new(JsonObject::new()),
                output_schema: None,
                annotations: None,
                icons: None,
                meta: None,
            })
            .collect()
    }

    fn resource_models(&self) -> Vec<Resource> {
        self.resources
            .lock()
            .unwrap()
            .iter()
            .map(|name| RawResource {
                uri: format!("resource://{name}"),
                name: name.clone(),
                title: None,
                description: None,
                mime_type: Some("text".into()),
                size: None,
                icons: None,
                meta: None,
            }
            .no_annotation())
            .collect()
    }

    fn resource_template_models(&self) -> Vec<ResourceTemplate> {
        self.resource_templates
            .lock()
            .unwrap()
            .iter()
            .map(|name| RawResourceTemplate {
                uri_template: format!("resource://{name}/{{id}}"),
                name: name.clone(),
                title: None,
                description: None,
                mime_type: Some("text".into()),
                icons: None,
            }
            .no_annotation())
            .collect()
    }

    fn prompt_models(&self) -> Vec<Prompt> {
        self.prompts
            .lock()
            .unwrap()
            .iter()
            .map(|name| Prompt::new(name.clone(), Some(format!("Prompt {name}")), None))
            .collect()
    }
}

impl rmcp::handler::server::ServerHandler for OneaiServerHandler {
    fn get_info(&self) -> ServerInfo {
        let caps = ServerCapabilities::builder()
            .enable_tools()
            .enable_prompts()
            .enable_resources()
            .build();
        ServerInfo {
            capabilities: caps,
            ..Default::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = self.tool_models();
        std::future::ready(Ok(ListToolsResult::with_all_items(tools)))
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_ {
        let resources = self.resource_models();
        std::future::ready(Ok(ListResourcesResult::with_all_items(resources)))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourceTemplatesResult, rmcp::ErrorData>> + Send + '_ {
        let templates = self.resource_template_models();
        std::future::ready(Ok(ListResourceTemplatesResult::with_all_items(templates)))
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, rmcp::ErrorData>> + Send + '_ {
        let prompts = self.prompt_models();
        std::future::ready(Ok(ListPromptsResult::with_all_items(prompts)))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let payload = serde_json::to_string(&request.arguments).unwrap_or_default();
        let msg = format!("Executed tool '{}' with args {}", request.name, payload);
        let content = RawContent::text(msg).no_annotation();
        std::future::ready(Ok(CallToolResult::success(vec![content])))
    }
}
