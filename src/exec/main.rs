// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::sync::Arc;

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;
use device_manager::{ManagerService, net_manager_server::NetManagerServer};
use proxy::{NetProxyManager, ProxyRun, ProxyManager};
use tonic::transport::Server;
use std::{sync::Mutex, env};

//======================================================================================================================
// main()
//======================================================================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Check command line arguments.
    if args.len() < 3 {
        println!("Usage: {} grpc_ip grpc_port\n", &args[0]);
        return Ok(());
    }

    let addr = format!("{}:{}", &args[1], &args[2]).parse()?;

    let (proxy, receiver) = NetProxyManager::new();
    let net_proxy_arc: Arc<Mutex<Box<dyn ProxyManager>>> = Arc::new(Mutex::new(Box::new(proxy)));
    let manager_service = ManagerService::new(net_proxy_arc);
    let polling_thread = std::thread::spawn( move || {
        let result = <NetProxyManager as ProxyRun>::run(receiver);
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
