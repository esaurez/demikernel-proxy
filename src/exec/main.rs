// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::Arc;

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;
use device_manager::{
    net_manager_server::NetManagerServer,
    ManagerService,
};
use proxy::{
    NetProxyManager,
    ProxyManager,
    ProxyRun,
    ProxyType,
};
use std::{
    env,
    sync::Mutex,
};
use tonic::transport::Server;

//======================================================================================================================
// main()
//======================================================================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Check command line arguments.
    if args.len() < 4 {
        println!("Usage: {} grpc_ip grpc_port proxy_type\n", &args[0]);
        return Ok(());
    }

    let addr = format!("{}:{}", &args[1], &args[2]).parse()?;

    // parse proxy type
    let proxy_type_str = &args[3];
    let proxy_type = if proxy_type_str == "tcp" {
        ProxyType::Tcp
    } else if proxy_type_str == "udp" {
        ProxyType::Udp
    } else {
        return Err(anyhow::anyhow!("Invalid proxy type"));
    };

    let (proxy, receiver) = NetProxyManager::new();
    let net_proxy_arc: Arc<Mutex<Box<dyn ProxyManager>>> = Arc::new(Mutex::new(Box::new(proxy)));
    let manager_service = ManagerService::new(net_proxy_arc);
    let polling_thread = std::thread::spawn(move || {
        let result = <NetProxyManager as ProxyRun>::run(receiver, proxy_type);
        if let Err(e) = result {
            return Err(e);
        }
        Ok(())
    });

    Server::builder()
        .add_service(NetManagerServer::new(manager_service))
        .serve(addr)
        .await?;

    polling_thread.join().unwrap()?;
    Ok(())
}
