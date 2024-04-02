// Copyright (c) Microsoft Corporation.

//======================================================================================================================
// Imports
//======================================================================================================================
use guid::Guid;
use hcs_sample_lib::hcsapi::HcsComputeSystem;
use hdv::{
    api::{
        DeviceHost,
        HdvApi,
        HdvDynDevice,
    },
    virtio_nimble::add_virtio_nimble_device,
    virtio_hdv::{
        HdvGuestMemoryCache,
        GUEST_MEMORY_DEFAULT_CACHE_SIZE,
    },
};

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        Mutex,
    },
    str::FromStr, 
};
use tonic::{
    Request,
    Response,
    Status,
};
use winapi::shared::guiddef::GUID;

use manager::{
    manager_response,
    net_manager_server::NetManager,
    DeviceEmulatorConfig,
    DeviceNetworkConfig,
    ManagerResponse,
};

use proxy::ProxyManager;

//======================================================================================================================
// Structures
//======================================================================================================================

pub mod manager {
    tonic::include_proto!("manager");
}

// Expose ProxyManagerServer as a public module
pub use manager::net_manager_server as net_manager_server;

#[derive(Debug)]
pub struct ManagerService {
    proxy_manager: Arc<Mutex<Box<dyn ProxyManager>>>, 
    // Map from VM_ID to store the devices
    devices: Arc<Mutex<HashMap<String, HdvDynDevice>>>,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================

impl ManagerService {
    pub fn new(proxy_manager: Arc<Mutex<Box<dyn ProxyManager>>>) -> Self {
        ManagerService {
            proxy_manager,
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl NetManager for ManagerService {
    async fn add_device_emulator(&self, request: Request<DeviceEmulatorConfig>) -> Result<Response<ManagerResponse>, Status> {
        let r = request.into_inner();
        let vm_id = r.vm_id.clone();
        let serverless_id = Guid::from_str(&r.nimble_device_unique_id).unwrap();
        let system: Result<_, _> = HcsComputeSystem::open_id(&vm_id.to_string());
        if let Err(result) = system {
            eprintln!("Failed to open compute system with result {:x}", result);
            return Err(Status::internal("error opening compute system"));
        }

        let system = system.unwrap();

        // Add the device to the system
        let hdv_api: HdvApi = Default::default();
        let host = DeviceHost::new(hdv_api, system.get_os_handle());
        if let Err(result) = host {
            eprintln!("CreateDeviceHost failed: HRESULT {:x}", result);
            return Err(Status::internal("error creating device host"));
        }

        let host = host.unwrap();
        let shared_cache = Arc::new(HdvGuestMemoryCache::new(GUEST_MEMORY_DEFAULT_CACHE_SIZE));

        // shared memory section is 64 KB
        let size = 64 * 1024;
        // section name is the vm id as a string
        let section_name = vm_id.to_string();
        // create a sparse mmap section of the corresponding size
        let section = sparse_mmap::alloc_shared_memory(size);

        let serverless = add_virtio_nimble_device(
                &host,
                shared_cache.clone(),
                &GUID::from(serverless_id),
                section_name,
                section.unwrap() as sparse_mmap::Mappable,
                size,
            );

        if let Err(result) = serverless {
            eprintln!("AddServerlessUvmDevice failed: HRESULT {:x}", result);
            return Err(Status::internal("error adding serverless uvm device"));
        }

        // Add the device to the map
        self.devices.lock().unwrap().insert(vm_id, serverless.unwrap());

        Ok(Response::new(ManagerResponse {
            status: manager_response::Status::Ok as i32,
        }))
    }


    async fn add_device_network(&self, request: Request<DeviceNetworkConfig>) -> Result<Response<ManagerResponse>, Status> {
        let r = request.into_inner();
        // Add the device to the proxy manager
        // \TODO: Use better error handling
        let net_socket_addr = SocketAddr::from_str(&r.net_address).unwrap();
        let vm_socket_addr = SocketAddr::from_str(&r.vm_address).unwrap();
        let add_result = self.proxy_manager.lock().unwrap().add_proxy(&r.vm_id, net_socket_addr, r.demikernel_libos_type , vm_socket_addr);
        if let Err(result) = add_result {
            eprintln!("AddProxy failed: {:?}", result);
            return Err(Status::internal("error adding proxy"));
        }

        Ok(Response::new(ManagerResponse {
            status: manager_response::Status::Ok as i32,
        }))
    }

    async fn remove_device_emulator(&self, request: Request<DeviceEmulatorConfig>) -> Result<Response<ManagerResponse>, Status> {
        let r = request.into_inner();

        // Remove the device from the map
        self.devices.lock().unwrap().remove(&r.vm_id);

        Ok(Response::new(ManagerResponse {
            status: manager_response::Status::Ok as i32,
        }))
    }

    async fn remove_device_network(&self, request: Request<DeviceNetworkConfig>) -> Result<Response<ManagerResponse>, Status> {
        let r = request.into_inner();

        // Remove the device from the proxy manager
        let remove_result = self.proxy_manager.lock().unwrap().remove_proxy(&r.vm_id);
        if let Err(result) = remove_result {
            eprintln!("RemoveProxy failed: {:?}", result);
            return Err(Status::internal("error removing proxy"));
        }

        Ok(Response::new(ManagerResponse {
            status: manager_response::Status::Ok as i32,
        }))
    }
}
