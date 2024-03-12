// Copyright (c) Microsoft Corporation.

//======================================================================================================================
// Protobuf generation
//======================================================================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("protos/manager.proto")?;
    Ok(())
}
