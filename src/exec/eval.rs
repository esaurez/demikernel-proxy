// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;
use std::env;

use device_manager::manager::{
    net_manager_client::NetManagerClient,
    EvalConfig,
};

//======================================================================================================================
// main()
//======================================================================================================================

#[tokio::main]
async fn main() -> Result<()> {
    const IP: &str = "127.0.0.1";
    const PORT: &str = "1200";
    let args: Vec<String> = env::args().collect();

    // Check command line arguments.
    if args.len() < 6 {
        println!(
            "Usage: {} vm_id segment_name num_iters data_size segment_size\n",
            &args[0]
        );
        return Ok(());
    }

    let vm_id: String = args[1].clone();
    let segment_name: String = args[2].clone();
    let num_iters: u32 = args[3].parse().unwrap();
    let data_size: u32 = args[4].parse().unwrap();
    let segment_size: u32 = args[5].parse().unwrap();

    let addr: String = format!("http://{}:{}", IP, PORT).parse()?;
    let mut client = NetManagerClient::connect(addr).await?;

    let request = tonic::Request::new(EvalConfig {
        vm_id: vm_id.clone(),
        segment_name: segment_name.clone(),
        iterations: num_iters.clone(),
        data_size: data_size.clone(),
        segment_size: segment_size.clone(),
    });

    let response = client.run_eval(request);

    if let Err(e) = response.await {
        println!("Failed to run eval: {:?}", e);
        return Ok(());
    }
    Ok(())
}
