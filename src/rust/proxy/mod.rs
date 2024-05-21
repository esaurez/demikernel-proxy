// Copyright (c) Microsoft Corporation.

#![feature(never_type)]
#![feature(extract_if)]
#![feature(hash_extract_if)]

pub mod constants;
mod tcp_in_libos;
mod udp_in_libos;

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;
#[cfg(feature = "virtio-shmem")]
use ::demikernel::pal::linux::virtio_shmem::SharedMemory;
// This feature is only for windows and nimble-shmem
#[cfg(all(feature = "nimble-shmem", target_os = "windows"))]
use ::demikernel::pal::windows::nimble_shm::SharedMemory;
#[cfg(feature = "profiler")]
use ::demikernel::perftools::profiler;
use ::demikernel::{
    demi_sgarray_t,
    demikernel::config::Config,
    runtime::types::{
        demi_opcode_t,
        demi_qresult_t,
    },
    timer,
    LibOS,
    LibOSName,
    QDesc,
    QToken,
};
use ::std::{
    collections::HashMap,
    fmt::Debug,
    io::Write,
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
    slice,
    sync::mpsc::{
        channel,
        Receiver,
        Sender,
    },
    time::{
        Duration,
        Instant,
    },
};
use ::yaml_rust::{
    Yaml,
    YamlLoader,
};

#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::SOCKADDR;
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::SOCKADDR_IN;

use crate::{
    tcp_in_libos::IncomingTcpLibos,
    udp_in_libos::IncomingUdpLibos,
};

use crate::constants::{
    AF_INET,
    AF_INET_FAM,
    SOCK_DGRAM,
    SOCK_STREAM,
};

#[cfg(target_os = "linux")]
pub const SOCK_DGRAM: i32 = libc::SOCK_DGRAM;
//======================================================================================================================
// Traits
//======================================================================================================================
pub struct AddRequest {
    vm_id: String,
    local_address: SocketAddr,
    in_libos: String,
    remote_addr: SocketAddr,
}

pub struct EvalRequest {
    vm_id: String,
    segment_name: String,
    data_size: u32,
    iterations: u32,
    segment_size: u32,
}

pub struct ProfileRequest {
    clean: bool,
}

pub enum ProxyRequest {
    // Add a new proxy
    Add(AddRequest),
    // String is the VM ID
    Remove(String),
    // Run an evaluation
    RunEval(EvalRequest),
    // Print profile
    PrintProfile(ProfileRequest),
}

pub trait ProxyManager: Send + Sync + Debug {
    fn add_proxy(
        &mut self,
        vm_id: &str,
        local_addr: SocketAddr,
        in_libos: String,
        remote_addr: SocketAddr,
    ) -> Result<()>;
    fn remove_proxy(&mut self, vm_id: &str) -> Result<()>;
    fn run_eval(
        &mut self,
        vm_id: &str,
        segment_name: &str,
        data_size: u32,
        iterations: u32,
        segment_size: u32,
    ) -> Result<()>;
    fn print_profile(&self, clean: bool) -> Result<()>;
}

pub trait ProxyRun {
    fn run(event_receiver: Receiver<ProxyRequest>, proxy_type: ProxyType) -> Result<()>;
}

pub trait Proxy {
    fn non_blocking_poll(
        &mut self,
        timeout_incoming: Option<Duration>,
        timeout_outgoing: Option<Duration>,
    ) -> Result<()>;
    fn issue_next_op(&mut self) -> Result<()>;
    fn run_eval(&mut self, eval: EvalRequest) -> Result<()>;
    fn print_profile(&mut self, clean: bool) -> Result<()>;
}

//======================================================================================================================
// Structures
//======================================================================================================================
pub enum ProxyType {
    Tcp,
    Udp,
    UdpTcp,
}

impl Clone for ProxyType {
    fn clone(&self) -> Self {
        match self {
            Self::Tcp => Self::Tcp,
            Self::Udp => Self::Udp,
            Self::UdpTcp => Self::UdpTcp,
        }
    }
}

struct TcpProxy {
    // Component that handles incoming flow.
    in_libos: IncomingTcpLibos,
    /// LibOS that handles outgoing flow.
    catloop: LibOS,
    /// Number of clients that are currently connected.
    nclients: usize,
    /// Remote socket address.
    remote_addr: SocketAddr,
    /// Queue descriptors of outgoing connections.
    outgoing_qds: HashMap<QDesc, bool>,
    /// Maps a queue descriptor of an outgoing connection to its respective incoming connection.
    outgoing_qds_map: HashMap<QDesc, QDesc>,
    /// Outgoing operations that are pending.
    outgoing_qts: Vec<QToken>,
    /// Maps a pending outgoing operation to its respective queue descriptor.
    outgoing_qts_map: HashMap<QToken, QDesc>,

    nano_per_cycle: f64,
    // Profile with the following meaning:
    // 0 -> Rdstc before poll
    // 1 -> Rdstc after polling incoming
    // 2 -> Rdstc after incoming sgalloc
    // 3 -> Rdstc after incoming copy
    // 4 -> Rdstc after incoming push 
    // 5 -> Rdstc after incoming handle
    // 6 -> Rdstc after polling outgoing
    // 7 -> Rdstc after outgoing sgalloc
    // 8 -> Rdstc after outgoing copy
    // 9 -> Rdstc after outgoing push
    // 10 -> Rdstc after outgoing handle 
    poll_vec_profile: [[u64; 12]; 20000],
    current_index: usize,
    something_happened: bool,
    current_polling_count: u64,
}

struct UdpProxy {
    /// LibOS that handles incoming flow.
    in_libos: IncomingUdpLibos,
    /// LibOS that handles outgoing flow.   
    catloop: LibOS,
    /// IP address to use for outgoing binding.
    outgoing_ip: Ipv4Addr,
    /// Next port to use for outgoing binding.
    outgoing_next_port: u16,
    /// Remote socket address to forward packets to.
    remote_addr: SocketAddr,
    /// Queue descriptors of outgoing sockets.
    outgoing_qds: HashMap<QDesc, bool>,
    /// Maps a queue descriptor of an outgoing socket to its respective incoming address.
    outgoing_qds_map: HashMap<QDesc, SocketAddr>,
    /// Outgoing operations that are pending.
    outgoing_qts: Vec<QToken>,
}

struct UdpTcpProxy {
    /// LibOS that handles incoming flow.
    in_libos: IncomingUdpLibos,
    /// LibOS that handles outgoing flow.   
    catloop: LibOS,
    /// Remote socket address to forward packets to.
    remote_addr: SocketAddr,
    // TCP for outgoing
    /// Queue descriptors of outgoing connections.
    outgoing_qds: HashMap<QDesc, bool>,
    /// Maps a queue descriptor of an outgoing connection to its respective incoming connection.
    outgoing_qds_map: HashMap<QDesc, SocketAddr>,
    /// Outgoing operations that are pending.
    outgoing_qts: Vec<QToken>,
    /// Maps a pending outgoing operation to its respective queue descriptor.
    outgoing_qts_map: HashMap<QToken, QDesc>,
}

pub struct NetProxyManager {
    // Sender for the control plane
    req_send: Sender<ProxyRequest>,
}

//======================================================================================================================
// Associated Functions
//======================================================================================================================
impl TcpProxy {
    /// Expected length for the array of pending outgoing operations.
    /// It controls the pre-allocated size of the array.
    /// Change this value accordingly so as to avoid allocations on the datapath.
    const OUTGOING_LENGTH: usize = 1024;

    /// Instantiates a TCP proxy that accepts incoming flows from `local_addr` and forwards them to `remote_addr`.
    pub fn new(vm_id: &str, local_addr: SocketAddr, libos_name: String, remote_addr: SocketAddr) -> Result<Self> {
        // Instantiate LibOS for handling incoming flows.
        let in_libos: IncomingTcpLibos = match IncomingTcpLibos::new(libos_name.into(), local_addr) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        let catmem_config: String = format!(
            "
catmem:
    name_prefix: {}
demikernel:
    local_ipv4_addr: {}
",
            vm_id,
            remote_addr.ip().to_string()
        );
        let config = YamlLoader::load_from_str(&catmem_config).unwrap();
        let config_obj: &Yaml = match &config[..] {
            &[ref c] => c,
            _ => Err(anyhow::format_err!("Wrong number of config objects")).unwrap(),
        };

        let demi_config = Config { 0: config_obj.clone() };
        // Instantiate LibOS for handling outgoing flows.
        let catloop: LibOS = match LibOS::new_with_config(LibOSName::Catloop, demi_config) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        Ok(Self {
            in_libos,
            catloop,
            nclients: 0,
            remote_addr,
            outgoing_qts: Vec::with_capacity(Self::OUTGOING_LENGTH),
            outgoing_qts_map: HashMap::default(),
            outgoing_qds: HashMap::default(),
            outgoing_qds_map: (HashMap::default()),
            nano_per_cycle: constants::measure_ns_per_cycle(),
            current_index: 0,
            something_happened: false,
            poll_vec_profile: [[0;12]; 20000],
            current_polling_count: 0,
        })
    }

    /// Registers an outgoing operation that is waiting for completion (pending).
    /// This function fails if the operation is already registered in the table of pending outgoing operations.
    fn register_outgoing_operation(&mut self, qd: QDesc, qt: QToken) -> Result<()> {
        timer!("proxy::register_outgoing");
        if self.outgoing_qts_map.insert(qt, qd).is_some() {
            anyhow::bail!("outgoing operation is already registered (qt={:?})", qt);
        }
        self.outgoing_qts.push(qt);
        Ok(())
    }

    /// Issues a `push()` operation in an outgoing flow.
    /// This function fails if the underlying `push()` operation fails.
    fn issue_outgoing_push(&mut self, qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        timer!("proxy::issue_outgoing_push");
        let qt: QToken = self.catloop.push(qd, &sga)?;

        // It is safe to call except() here, because we just issued the `push()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_outgoing_operation(qd, qt)
            .expect("outgoing push() operration is already registered");

        Ok(())
    }

    /// Issues a `pop()` operation in an outgoing flow.
    /// This function fails if the underlying `pop()` operation fails.
    fn issue_outgoing_pop(&mut self, qd: QDesc) -> Result<()> {
        timer!("proxy::issue_outgoing_pop");
        let qt: QToken = self.catloop.pop(qd, None)?;

        // It is safe to call except() here, because we just issued the `pop()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_outgoing_operation(qd, qt)
            .expect("outgoing pop() operration is already registered");

        // Set the flag to indicate that this flow has an inflight `pop()` operation.
        // It is safe to call except() here, because `qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let catloop_inflight_pop: &mut bool = self
            .outgoing_qds
            .get_mut(&qd)
            .expect("queue descriptor should be registered");
        *catloop_inflight_pop = true;

        Ok(())
    }

    /// Handles the completion of an `accept()` operation.
    /// This function fails if we we fail to setup a connection with the remote address.
    fn handle_incoming_accept(&mut self, qr: &demi_qresult_t) -> Result<()> {
        timer!("proxy::handle_incoming_accept");
        let new_client_socket: QDesc = unsafe { qr.qr_value.ares.qd.into() };

        // Setup remote connection.
        let new_server_socket: QDesc = match self.catloop.socket(AF_INET, SOCK_STREAM, 0) {
            Ok(qd) => qd,
            Err(e) => {
                println!("ERROR: failed to create socket (error={:?})", e);
                anyhow::bail!("failed to create socket: {:?}", e.cause)
            },
        };

        // Connect to remote address.
        match self.catloop.connect(new_server_socket, self.remote_addr) {
            // Operation succeeded, register outgoing operation.
            Ok(qt) => self.register_outgoing_operation(new_server_socket, qt)?,
            // Operation failed, close socket.
            Err(e) => {
                if let Err(e) = self.catloop.close(new_server_socket) {
                    // Failed to close socket, log error.
                    println!("ERROR: close failed (error={:?})", e);
                    println!("WARN: leaking socket descriptor (sockqd={:?})", new_server_socket);
                }
                anyhow::bail!("failed to connect socket: {:?}", e)
            },
        };

        // Accept another connection.
        if let Err(e) = self.in_libos.issue_accept() {
            // Failed to issue accept operation, log error.
            println!("ERROR: accept failed (error={:?})", e);
            return Err(e);
        };

        self.in_libos.insert_qds(new_server_socket, new_client_socket);
        self.outgoing_qds.insert(new_server_socket, false);
        self.outgoing_qds_map.insert(new_client_socket, new_server_socket);

        Ok(())
    }

    /// Handles the completion of a `connect()` operation.
    fn handle_outgoing_connect(&mut self, qr: &demi_qresult_t) {
        timer!("proxy::handle_outgoing_connect");
        let catloop_qd: QDesc = qr.qr_qd.into();

        let in_libos_qd = self.in_libos.get_incoming_qd(catloop_qd);
        // Issue a `pop()` operation in the outgoing flow.
        if let Err(e) = self.in_libos.issue_incoming_pop(in_libos_qd) {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
        }

        self.nclients += 1;
        println!("INFO: {:?} clients connected", self.nclients);
    }

    /// Handles the completion of a `pop()` operation on an incoming flow.
    fn handle_incoming_pop(&mut self, qr: &demi_qresult_t) {
        timer!("proxy::handle_incoming_pop");
        let incoming_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };
        let in_libos_qd: QDesc = qr.qr_qd.into();

        // It is safe to call except() here, because `in_libos_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let catloop_qd: QDesc = *self
            .outgoing_qds_map
            .get(&in_libos_qd)
            .expect("queue descriptor should be registered");

        // Check if client closed connection.
        if incoming_sga.sga_segs[0].sgaseg_len == 0 {
            println!("INFO: client closed connection");
            self.close_client(in_libos_qd, catloop_qd);
            return;
        }

        // Push SGA to concerned outgoing flow.
        let src: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = incoming_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(outgoing_sga) = self.catloop.sgaalloc(len) {
            { // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[2] = constants::get_current_rdtscp();
            }
            timer!("proxy::handle_incoming_pop::processing");
            // Copy.
            let dest: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);
            { // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[3] = constants::get_current_rdtscp();
            }

            // Issue `push()` operation.
            if let Err(e) = self.issue_outgoing_push(catloop_qd, &outgoing_sga) {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
            }

            {  // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[4] = constants::get_current_rdtscp();
            }

            // Release outgoing SGA.
            if let Err(e) = self.catloop.sgafree(outgoing_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking outgoing sga");
            }
        }

        // Release incoming SGA.
        if let Err(e) = self.in_libos.sgafree(incoming_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking incoming sga");
        }

        // Pop more data from incoming flow.
        if let Err(e) = self.in_libos.issue_incoming_pop(in_libos_qd) {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
        }
    }

    /// Handles the completion of a `pop()` operation on an outgoing flow.
    fn handle_outgoing_pop(&mut self, qr: &demi_qresult_t) {
        timer!("proxy::handle_outgoing_pop");
        let outgoing_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };
        let catloop_qd: QDesc = qr.qr_qd.into();

        let in_libos_qd = self.in_libos.get_incoming_qd(catloop_qd);

        // Check if server aborted connection.
        if outgoing_sga.sga_segs[0].sgaseg_len == 0 {
            unimplemented!("server aborted connection");
        }

        // Push SGA to concerned incoming flow.
        let src: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = outgoing_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(incoming_sga) = self.in_libos.sgaalloc(len) {
            {  // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[7] = constants::get_current_rdtscp();
            }

            timer!("proxy::handle_outgoing_pop::processing");
            // Copy.
            let dest: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);

            {  // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[8] = constants::get_current_rdtscp();
            }

            // Issue `push()` operation.
            if let Err(e) = self.in_libos.issue_incoming_push(in_libos_qd, &incoming_sga) {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
            }
            {  // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[9] = constants::get_current_rdtscp();
            }

            // Release incoming SGA.
            if let Err(e) = self.in_libos.sgafree(incoming_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking incoming sga");
            }
        }

        // Release outgoing SGA.
        if let Err(e) = self.catloop.sgafree(outgoing_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking outgoing sga");
        }

        // Pop data from outgoing flow.
        if let Err(e) = self.issue_outgoing_pop(catloop_qd) {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
        }
    }

    /// Handles the completion of a `push()` operation on an outgoing flow.
    /// This will issue a pop operation on the outgoing connection, if none is inflight.
    fn handle_outgoing_push(&mut self, qr: &demi_qresult_t) {
        timer!("proxy::handle_outgoing_push");
        // Extract queue descriptor of outgoing connection.
        let outgoing_qd: QDesc = qr.qr_qd.into();

        // It is safe to call except() here, because `outgoing_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let has_inflight_pop: bool = self
            .outgoing_qds
            .get_mut(&outgoing_qd)
            .expect("queue descriptor should be registered")
            .to_owned();

        // Issue a pop operation if none is inflight.
        if !has_inflight_pop {
            println!("INFO: issuing outgoing pop (qd={:?})", outgoing_qd);
            if let Err(e) = self.issue_outgoing_pop(outgoing_qd) {
                // Failed to issue pop operation, log error.
                println!("ERROR: pop failed (error={:?})", e);
            }
        }
    }

    // Closes an incoming flow.
    fn close_client(&mut self, in_libos_socket: QDesc, catloop_socket: QDesc) {
        match self.in_libos.close(in_libos_socket) {
            Ok(_) => {
                self.outgoing_qds_map.remove(&in_libos_socket).unwrap();
            },
            Err(e) => println!("ERROR: failed to close socket (error={:?})", e),
        }

        match self.catloop.close(catloop_socket) {
            Ok(_) => {
                println!("handle cancellation of tokens (catloop_socket={:?})", catloop_socket);
                self.outgoing_qds.remove(&catloop_socket).unwrap();
                self.in_libos.remove_qds_map(&catloop_socket).unwrap();
                let qts_drained: HashMap<QToken, QDesc> =
                    self.outgoing_qts_map.extract_if(|_k, v| v == &catloop_socket).collect();
                let _: Vec<_> = self.outgoing_qts.extract_if(|x| qts_drained.contains_key(x)).collect();
            },
            Err(e) => println!("ERROR: failed to close socket (error={:?})", e),
        }
        self.nclients -= 1;
    }

    /// Polls outgoing operations that are pending, with a timeout.
    ///
    /// If any pending operation completes when polling, its result value is
    /// returned. If the timeout expires before an operation completes, or an
    /// error is encountered, None is returned instead.
    fn poll_outgoing(&mut self, timeout: Option<Duration>) -> Option<demi_qresult_t> {
        timer!("proxy::poll_outgoing");
        match self.catloop.wait_any(&self.outgoing_qts, timeout) {
            Ok((idx, qr)) => {
                self.unregister_outgoing_operation(idx);
                Some(qr)
            },
            Err(e) if e.errno == libc::ETIMEDOUT => None,
            Err(e) => {
                println!("ERROR: unexpected error while polling outgoing queue (error={:?})", e);
                None
            },
        }
    }

    fn unregister_outgoing_operation(&mut self, index: usize) {
        let qt: QToken = self.outgoing_qts.remove(index);
        // It is safe to call except() here, because `qt` is ensured to be in the table of pending operations.
        // All queue tokens are registered in the table of pending operations when they are issued.
        self.outgoing_qts_map
            .remove(&qt)
            .expect("queue token should be registered");
    }

    /// Copies `len` bytes from `src` to `dest`.
    fn copy(src: *mut libc::c_uchar, dest: *mut libc::c_uchar, len: usize) {
        timer!("proxy::copy");
        let src: &mut [u8] = unsafe { slice::from_raw_parts_mut(src, len) };
        let dest: &mut [u8] = unsafe { slice::from_raw_parts_mut(dest, len) };
        dest.clone_from_slice(src);
    }
}

impl Proxy for TcpProxy {
    fn issue_next_op(&mut self) -> Result<()> {
        self.in_libos.issue_accept()
    }

    fn print_profile(&mut self, clean: bool) -> Result<()> {
        if clean {
            self.current_index = 0;
            self.current_polling_count = 0;
        } else {

            println!("Nano per cycle: {};", self.nano_per_cycle);

            println!("Rdtsc before poll; Rdtsc after polling incoming; Rdtsc after incoming sgalloc; Rdtsc after incoming copy; Rdtsc after incoming push; Rdtsc after incoming handle; Rdtsc after polling outgoing; Rdtsc after outgoing sgalloc; Rdtsc after outgoing copy; Rdtsc after outgoing push; Rdtsc after outgoing handle; pre-polling count;");

           // Iterate from 0 to current_index
           for i in 0..self.current_index {
               let current_profile: &[u64; 12] = &self.poll_vec_profile[i];
               println!(
                   "{}; {}; {}; {}; {}; {}; {}; {}; {}; {}; {}; {}",
                   current_profile[0],
                   current_profile[1],
                   current_profile[2],
                   current_profile[3],
                   current_profile[4],
                   current_profile[5],
                   current_profile[6],
                   current_profile[7],
                   current_profile[8],
                   current_profile[9],
                   current_profile[10],
                   current_profile[11]
               );
           }

           self.current_index = 0;
           self.current_polling_count = 0;
        }

        println!("Print profile catloop");
        // self.catloop.print_profile();
        println!("Print profile in libos");
        self.in_libos.print_profile();
        println!("Done printing profile");
        Ok(())
    }

    fn non_blocking_poll(
        &mut self,
        timeout_incoming: Option<Duration>,
        timeout_outgoing: Option<Duration>,
    ) -> Result<()> {
        self.something_happened = false;
        timer!("proxy::non_blocking_poll");
        { // Borrow scope
            let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
            current_profile[0] = constants::get_current_rdtscp();
        }
        // Poll incoming flows.
        if let Some(qr) = self.in_libos.poll_incoming(timeout_incoming) {
            self.something_happened = true;
            { // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                current_profile[1] = constants::get_current_rdtscp();
            }
            timer!("proxy::non_blocking_poll::incoming");
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_incoming_accept(&qr)?,
                demi_opcode_t::DEMI_OPC_POP => self.handle_incoming_pop(&qr),
                demi_opcode_t::DEMI_OPC_PUSH => self.in_libos.handle_incoming_push(&qr),
                demi_opcode_t::DEMI_OPC_FAILED => {
                    // Check if this is an unrecoverable error.
                    if qr.qr_ret != libc::ECONNRESET as i64 {
                        anyhow::bail!("operation failed")
                    }
                    println!("WARN: client reset connection");
                    let in_libos_qd: QDesc = qr.qr_qd.into();
                    // It is safe to expect here because the queue descriptor must have been registered.
                    // All queue descriptors are registered when the connection is established.
                    let catloop_qd: QDesc = *self
                        .outgoing_qds_map
                        .get(&in_libos_qd)
                        .expect("queue descriptor not registered");
                    self.close_client(in_libos_qd, catloop_qd);
                },
                _ => unreachable!(),
            };
        }

        { // Borrow scope
            let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
            current_profile[5] = constants::get_current_rdtscp();
        }

        // Poll outgoing flows.
        if let Some(qr) = self.poll_outgoing(timeout_outgoing) {
            { // Borrow scope
                let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
                self.something_happened = true;
                current_profile[6] = constants::get_current_rdtscp();
            }
            timer!("proxy::non_blocking_poll::outgoing");
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_CONNECT => self.handle_outgoing_connect(&qr),
                demi_opcode_t::DEMI_OPC_POP => self.handle_outgoing_pop(&qr),
                demi_opcode_t::DEMI_OPC_PUSH => self.handle_outgoing_push(&qr),
                demi_opcode_t::DEMI_OPC_FAILED => {
                    // Check if this is an unrecoverable error.
                    if qr.qr_ret != libc::ECONNRESET as i64 {
                        anyhow::bail!("operation failed")
                    }
                    println!("WARN: server reset connection");
                    let catloop_socket: QDesc = qr.qr_qd.into();
                    let in_libos_socket: QDesc = self.in_libos.get_incoming_qd(catloop_socket);
                    self.close_client(in_libos_socket, catloop_socket);
                },
                _ => unreachable!(),
            };
        }

        { // Borrow scope
            let current_profile: &mut [u64; 12] = &mut self.poll_vec_profile[self.current_index];
            current_profile[10] = constants::get_current_rdtscp();

            if self.something_happened || current_profile[10] - current_profile[0] > 100000 {
                current_profile[11] =self.current_polling_count;
                self.current_polling_count = 0;
                self.current_index += 1;

                if self.current_index == 20000 {
                    self.print_profile(false);
                }
            } else {
              self.current_polling_count += 1;
            }
        }

        Ok(())
    }

    fn run_eval(&mut self, eval: EvalRequest) -> Result<()> {
        // Start a thread that will run the evaluation
        std::thread::spawn(move || {
            // Start time measurement
            let begin = Instant::now();
            // Get the segment
            let formatted_name = format!("{}-{}", eval.vm_id, eval.segment_name);
            let mut segment = match SharedMemory::open(&formatted_name, eval.segment_size as usize) {
                Ok(segment) => segment,
                Err(e) => {
                    // Log and panic
                    // \TODO Better error handling
                    println!("Error getting segment: {:?}", e);
                    return;
                },
            };

            let shm = segment.as_mut_ptr();

            let end_segment_creation = Instant::now();
            let segment_nano_duration = end_segment_creation.duration_since(begin).as_nanos();
            println!("Segment creation took: {} ns", segment_nano_duration);

            let input_data = vec![1u8; eval.data_size as usize];
            let begin_iteration = Instant::now();
            for _ in 0..eval.iterations {
                // Create a slice from the shared memory
                let mut segment_slice = unsafe { std::slice::from_raw_parts_mut(shm, eval.segment_size as usize) };
                // Write data to the segment
                match segment_slice.write_all(input_data.as_slice()) {
                    Ok(_) => {},
                    Err(e) => {
                        // Log and panic
                        // \TODO Better error handling
                        println!("Error writing to segment: {:?}", e);
                        return;
                    },
                }

                // Create a slice from the shared memory
                let read_slice = unsafe { std::slice::from_raw_parts(shm, eval.segment_size as usize) };

                // wait for the segment slice to be zeros again
                while read_slice.iter().any(|&x| x != 0) {
                    // Do nothing and poll
                }
            }
            let end_iteration = Instant::now();
            // Get the average in nanoseconds
            let iteration_nano_duration =
                (end_iteration.duration_since(begin_iteration).as_nanos() as f64) / (eval.iterations as f64);
            println!("Iteration took: {} ns in average", iteration_nano_duration);
        });
        Ok(())
    }
}

impl UdpProxy {
    /// Expected length for the array of pending outgoing operations.
    /// It controls the pre-allocated size of the array.
    /// Change this value accordingly so as to avoid allocations on the datapath.
    const OUTGOING_LENGTH: usize = 1024;

    /// Instantiates a TCP proxy that accepts incoming flows from `local_addr` and forwards them to `remote_addr`.
    pub fn new(vm_id: &str, local_addr: SocketAddr, libos_name: String, remote_addr: SocketAddr) -> Result<Self> {
        // Instantiate LibOS for handling incoming flows.
        let in_libos: IncomingUdpLibos = match IncomingUdpLibos::new(libos_name.into(), local_addr) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        let catmem_config: String = format!(
            "
catmem:
    name_prefix: {}
catnip:
    my_ipv4_addr: {}
",
            vm_id,
            remote_addr.ip().to_string()
        );
        let config = YamlLoader::load_from_str(&catmem_config).unwrap();
        let config_obj: &Yaml = match &config[..] {
            &[ref c] => c,
            _ => Err(anyhow::format_err!("Wrong number of config objects")).unwrap(),
        };

        let demi_config = Config { 0: config_obj.clone() };
        // Instantiate LibOS for handling outgoing flows.
        let catloop: LibOS = match LibOS::new_with_config(LibOSName::Catloop, demi_config) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        //\TODO update outgoing_ip and outgoing_next_port
        Ok(Self {
            in_libos,
            catloop,
            remote_addr,
            outgoing_ip: Ipv4Addr::new(127, 0, 0, 1),
            outgoing_next_port: 20000,
            outgoing_qds: HashMap::default(),
            outgoing_qds_map: (HashMap::default()),
            outgoing_qts: Vec::with_capacity(Self::OUTGOING_LENGTH),
        })
    }

    /// Registers an outgoing operation that is waiting for completion (pending).
    /// This function fails if the operation is already registered in the table of pending outgoing operations.
    fn register_outgoing_operation(&mut self, qt: QToken) {
        self.outgoing_qts.push(qt);
    }

    /// Issues a `push()` operation in an outgoing flow.
    /// This function fails if the underlying `push()` operation fails.
    fn issue_outgoing_push(&mut self, catloop_qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        let qt: QToken = self.catloop.pushto(catloop_qd, &sga, self.remote_addr)?;

        // It is safe to call except() here, because we just issued the `push()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_outgoing_operation(qt);

        Ok(())
    }

    /// Issues a `pop()` operation in an outgoing flow.
    /// This function fails if the underlying `pop()` operation fails.
    fn issue_outgoing_pop(&mut self, qd: QDesc) -> Result<()> {
        let qt: QToken = self.catloop.pop(qd, None)?;

        self.register_outgoing_operation(qt);

        // Set the flag to indicate that this flow has an inflight `pop()` operation.
        // It is safe to call except() here, because `qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let catloop_inflight_pop: &mut bool = self
            .outgoing_qds
            .get_mut(&qd)
            .expect("queue descriptor should be registered");
        *catloop_inflight_pop = true;

        Ok(())
    }

    fn get_next_port(&mut self) -> Result<u16> {
        // \TODO This is a very simple way to get the next port, it should be improved
        // This will run out of ports, and it is wasting one port
        match self.outgoing_next_port.checked_add(1) {
            Some(port) => {
                self.outgoing_next_port = port;
                Ok(port)
            },
            None => Err(anyhow::format_err!("No more ports available")),
        }
    }

    #[cfg(target_os = "linux")]
    /// Converts a [sockaddr] into a port number.
    pub fn sockaddr_to_socketaddrv4(saddr: libc::sockaddr) -> Result<SocketAddr> {
        // TODO: Change the logic below and rename this function once we support V6 addresses as well.
        let sin: libc::sockaddr_in = unsafe { mem::transmute(saddr) };
        if sin.sin_family != libc::AF_INET as u16 {
            anyhow::bail!("communication domain not supported");
        };
        let addr: Ipv4Addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port: u16 = u16::from_be(sin.sin_port);
        Ok(SocketAddr::new(ipv4_addr, port))
    }

    #[cfg(target_os = "windows")]
    /// Converts a [sockaddr] into a port number.
    pub fn sockaddr_to_socketaddrv4(saddr: SOCKADDR) -> Result<SocketAddr> {
        // Casting to SOCKADDR_IN
        let addr_in: SOCKADDR_IN = unsafe { std::mem::transmute(saddr) };

        if addr_in.sin_family != AF_INET_FAM {
            anyhow::bail!("communication domain not supported");
        };
        // Extracting IPv4 address and port
        let ipv4_addr = unsafe {
            Ipv4Addr::new(
                addr_in.sin_addr.S_un.S_un_b.s_b4,
                addr_in.sin_addr.S_un.S_un_b.s_b3,
                addr_in.sin_addr.S_un.S_un_b.s_b2,
                addr_in.sin_addr.S_un.S_un_b.s_b1,
            )
        };
        let port: u16 = u16::from_be(addr_in.sin_port);

        // Creating SocketAddrV4
        Ok(SocketAddr::new(IpAddr::V4(ipv4_addr), port))
    }

    fn create_outgoing_socket(&mut self, ip_addr: &SocketAddr) -> Result<QDesc> {
        // Create outgoing socket.
        let catloop_qd: QDesc = match self.catloop.socket(AF_INET, SOCK_DGRAM, 1) {
            Ok(qd) => qd,
            Err(e) => {
                println!("ERROR: failed to create socket (error={:?})", e);
                anyhow::bail!("failed to create socket: {:?}", e.cause)
            },
        };

        // bind socket to new local address
        let next_port = self.get_next_port()?;
        let client_socket_address = SocketAddr::new(std::net::IpAddr::V4(self.outgoing_ip), next_port);
        // bind socket to local address
        match self.catloop.bind(catloop_qd.clone(), client_socket_address) {
            Ok(_) => {},
            Err(e) => {
                println!("ERROR: failed to bind socket (error={:?})", e);
                anyhow::bail!("failed to bind socket: {:?}", e.cause)
            },
        };

        self.outgoing_qds.insert(catloop_qd.clone(), false);
        self.outgoing_qds_map.insert(catloop_qd.clone(), ip_addr.clone());
        self.in_libos.insert_incoming_map(ip_addr.clone(), catloop_qd.clone());

        Ok(catloop_qd)
    }

    /// Handles the completion of a `pop()` operation on an incoming flow.
    fn handle_incoming_pop(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let incoming_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };

        // Get the incoming address
        let ip_addr = Self::sockaddr_to_socketaddrv4(unsafe { qr.qr_value.sga.sga_addr })?;

        let catloop_qd_opt: Option<&QDesc> = self.in_libos.get_incoming_map(&ip_addr);

        let catloop_qd: QDesc = match catloop_qd_opt {
            Some(catloop_qd) => *catloop_qd,
            None => {
                // Create outgoing socket.
                self.create_outgoing_socket(&ip_addr)?
            },
        };

        // Push SGA to concerned outgoing flow.
        let src: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = incoming_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(outgoing_sga) = self.catloop.sgaalloc(len) {
            // Copy.
            let dest: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);

            // Issue `push()` operation.
            if let Err(e) = self.issue_outgoing_push(catloop_qd, &outgoing_sga) {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
                return Err(e);
            }

            // Release outgoing SGA.
            if let Err(e) = self.catloop.sgafree(outgoing_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking outgoing sga");
                return Err(e.into());
            }
        }

        // Release incoming SGA.
        if let Err(e) = self.in_libos.sgafree(incoming_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking incoming sga");
            return Err(e.into());
        }

        // Pop more data from incoming flow.
        if let Err(e) = self.in_libos.issue_incoming_pop() {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
            return Err(e);
        }
        return Ok(());
    }

    /// Handles the completion of a `pop()` operation on an outgoing flow.
    fn handle_outgoing_pop(&mut self, qr: &demi_qresult_t) -> Result<()> {
        let outgoing_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };
        let catloop_qd: QDesc = qr.qr_qd.into();
        // Push SGA to concerned incoming flow.
        let src: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = outgoing_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(incoming_sga) = self.in_libos.sgaalloc(len) {
            // Copy.
            let dest: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);

            let client_address: &SocketAddr = match self.outgoing_qds_map.get(&catloop_qd) {
                Some(address) => address,
                None => {
                    return Err(anyhow::format_err!("No address found for incoming push"));
                },
            };

            // Issue `push()` operation.
            if let Err(e) = self
                .in_libos
                .issue_incoming_pushto(catloop_qd, &incoming_sga, *client_address)
            {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
                return Err(e);
            }

            // Release incoming SGA.
            if let Err(e) = self.in_libos.sgafree(incoming_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking incoming sga");
                return Err(e.into());
            }
        }

        // Release outgoing SGA.
        if let Err(e) = self.catloop.sgafree(outgoing_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking outgoing sga");
            return Err(e.into());
        }

        // Pop data from outgoing flow.
        if let Err(e) = self.issue_outgoing_pop(catloop_qd) {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
            return Err(e);
        }

        return Ok(());
    }

    /// Handles the completion of a `pushto()` operation on an incoming flow.
    /// This will issue a pop operation on the incoming connection, if none is inflight.
    fn handle_incoming_push(&mut self) -> Result<()> {
        self.in_libos.handle_incoming_push()
    }

    /// Handles the completion of a `push()` operation on an outgoing flow.
    /// This will issue a pop operation on the outgoing connection, if none is inflight.
    fn handle_outgoing_push(&mut self, qr: &demi_qresult_t) -> Result<()> {
        // Extract queue descriptor of outgoing connection.
        let outgoing_qd: QDesc = qr.qr_qd.into();

        // It is safe to call except() here, because `outgoing_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let has_inflight_pop: bool = self
            .outgoing_qds
            .get_mut(&outgoing_qd)
            .expect("queue descriptor should be registered")
            .to_owned();

        // Issue a pop operation if none is inflight.
        if !has_inflight_pop {
            println!("INFO: issuing outgoing pop (qd={:?})", outgoing_qd);
            if let Err(e) = self.issue_outgoing_pop(outgoing_qd) {
                // Failed to issue pop operation, log error.
                println!("ERROR: pop failed (error={:?})", e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Polls outgoing operations that are pending, with a timeout.
    ///
    /// If any pending operation completes when polling, its result value is
    /// returned. If the timeout expires before an operation completes, or an
    /// error is encountered, None is returned instead.
    fn poll_outgoing(&mut self, timeout: Option<Duration>) -> Option<demi_qresult_t> {
        match self.catloop.wait_any(&self.outgoing_qts, timeout) {
            Ok((idx, qr)) => {
                self.unregister_outgoing_operation(idx);
                Some(qr)
            },
            Err(e) if e.errno == libc::ETIMEDOUT => None,
            Err(e) => {
                println!("ERROR: unexpected error while polling outgoing queue (error={:?})", e);
                None
            },
        }
    }

    fn unregister_outgoing_operation(&mut self, index: usize) {
        let _: QToken = self.outgoing_qts.swap_remove(index);
    }

    /// Copies `len` bytes from `src` to `dest`.
    fn copy(src: *mut libc::c_uchar, dest: *mut libc::c_uchar, len: usize) {
        let src: &mut [u8] = unsafe { slice::from_raw_parts_mut(src, len) };
        let dest: &mut [u8] = unsafe { slice::from_raw_parts_mut(dest, len) };
        dest.clone_from_slice(src);
    }

    /// Handles the completion of an unexpected operation.
    fn handle_unexpected(&mut self, op_name: &str, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let qt: QToken = qr.qr_qt.into();
        println!(
            "WARN: unexpected {} operation completed, ignoring (qd={:?}, qt={:?})",
            op_name, qd, qt
        );
        Ok(())
    }
}

impl Proxy for UdpProxy {
    fn issue_next_op(&mut self) -> Result<()> {
        self.in_libos.issue_incoming_pop()
    }

    fn print_profile(&mut self, _clean: bool) -> Result<()> {
        Ok(())
    }

    fn non_blocking_poll(
        &mut self,
        timeout_incoming: Option<Duration>,
        timeout_outgoing: Option<Duration>,
    ) -> Result<()> {
        // Poll incoming flows.
        if let Some(qr) = self.in_libos.poll_incoming(timeout_incoming) {
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_POP => self.handle_incoming_pop(&qr)?,
                demi_opcode_t::DEMI_OPC_PUSH => self.handle_incoming_push()?,
                demi_opcode_t::DEMI_OPC_FAILED => {
                    println!("ERROR: incoming operation failed (error={:?})", qr.qr_ret);
                    if let Err(e) = self.in_libos.issue_incoming_pop() {
                        println!("ERROR: failed to issue incoming pop (error={:?})", e);
                    }
                    anyhow::bail!("operation failed")
                },
                demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("incoming_accept", &qr)?,
                demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("incoming_invalid", &qr)?,
                demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("incoming_close", &qr)?,
                demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("incoming_connect", &qr)?,
            };
        }

        // Poll outgoing flows.
        if let Some(qr) = self.poll_outgoing(timeout_outgoing) {
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_POP => self.handle_outgoing_pop(&qr)?,
                demi_opcode_t::DEMI_OPC_PUSH => self.handle_outgoing_push(&qr)?,
                demi_opcode_t::DEMI_OPC_FAILED => {
                    println!("ERROR: outgoing operation failed (error={:?})", qr.qr_ret);
                    let catloop_qd: QDesc = qr.qr_qd.into();
                    if let Err(e) = self.issue_outgoing_pop(catloop_qd) {
                        println!("ERROR: failed to issue outgoing pop (error={:?})", e);
                    }
                    anyhow::bail!("operation failed")
                },
                demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("outgoing_accept", &qr)?,
                demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("outgoing_invalid", &qr)?,
                demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("outgoing_close", &qr)?,
                demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("outgoing_connect", &qr)?,
            };
        }

        Ok(())
    }

    fn run_eval(&mut self, _eval: EvalRequest) -> Result<()> {
        // Return not implemented error
        println!("Error: run_eval not implemented for UdpProxy");
        Err(anyhow::format_err!("Not implemented"))
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        // Close local socket
        if let Err(e) = self.in_libos.close() {
            println!("ERROR: {:?}", e);
        }

        // Close all client sockets
        for (qd, _) in self.outgoing_qds.iter() {
            if let Err(e) = self.catloop.close(*qd) {
                println!("ERROR: {:?}", e);
            }
        }
    }
}

impl UdpTcpProxy {
    /// Expected length for the array of pending outgoing operations.
    /// It controls the pre-allocated size of the array.
    /// Change this value accordingly so as to avoid allocations on the datapath.
    const OUTGOING_LENGTH: usize = 1024;

    /// Instantiates a TCP proxy that accepts incoming flows from `local_addr` and forwards them to `remote_addr`.
    pub fn new(vm_id: &str, local_addr: SocketAddr, libos_name: String, remote_addr: SocketAddr) -> Result<Self> {
        timer!("proxy::new");
        // Instantiate LibOS for handling incoming flows.
        let in_libos: IncomingUdpLibos = match IncomingUdpLibos::new(libos_name.into(), local_addr) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        let catmem_config: String = format!(
            "
catmem:
    name_prefix: {}
catnip:
    my_ipv4_addr: {}
",
            vm_id,
            remote_addr.ip().to_string()
        );
        let config = YamlLoader::load_from_str(&catmem_config).unwrap();
        let config_obj: &Yaml = match &config[..] {
            &[ref c] => c,
            _ => Err(anyhow::format_err!("Wrong number of config objects")).unwrap(),
        };

        let demi_config = Config { 0: config_obj.clone() };
        // Instantiate LibOS for handling outgoing flows.
        let catloop: LibOS = match LibOS::new_with_config(LibOSName::Catloop, demi_config) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        Ok(Self {
            in_libos,
            catloop,
            remote_addr,
            outgoing_qts: Vec::with_capacity(Self::OUTGOING_LENGTH),
            outgoing_qts_map: HashMap::default(),
            outgoing_qds: HashMap::default(),
            outgoing_qds_map: (HashMap::default()),
        })
    }

    /// Registers an outgoing operation that is waiting for completion (pending).
    /// This function fails if the operation is already registered in the table of pending outgoing operations.
    fn register_outgoing_operation(&mut self, qd: QDesc, qt: QToken) -> Result<()> {
        if self.outgoing_qts_map.insert(qt, qd).is_some() {
            anyhow::bail!("outgoing operation is already registered (qt={:?})", qt);
        }
        self.outgoing_qts.push(qt);
        Ok(())
    }

    /// Issues a `push()` operation in an outgoing flow.
    /// This function fails if the underlying `push()` operation fails.
    fn issue_outgoing_push(&mut self, qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        timer!("proxy::issue_outgoing_push");
        let qt: QToken = self.catloop.push(qd, &sga)?;

        // It is safe to call except() here, because we just issued the `push()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_outgoing_operation(qd, qt)
            .expect("outgoing push() operration is already registered");

        Ok(())
    }

    /// Issues a `pop()` operation in an outgoing flow.
    /// This function fails if the underlying `pop()` operation fails.
    fn issue_outgoing_pop(&mut self, qd: QDesc) -> Result<()> {
        timer!("proxy::issue_outgoing_pop");
        let qt: QToken = self.catloop.pop(qd, None)?;

        // It is safe to call except() here, because we just issued the `pop()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_outgoing_operation(qd, qt)
            .expect("outgoing pop() operration is already registered");

        // Set the flag to indicate that this flow has an inflight `pop()` operation.
        // It is safe to call except() here, because `qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let catloop_inflight_pop: &mut bool = self
            .outgoing_qds
            .get_mut(&qd)
            .expect("queue descriptor should be registered");
        *catloop_inflight_pop = true;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// Converts a [sockaddr] into a port number.
    pub fn sockaddr_to_socketaddrv4(saddr: libc::sockaddr) -> Result<SocketAddr> {
        // TODO: Change the logic below and rename this function once we support V6 addresses as well.
        let sin: libc::sockaddr_in = unsafe { mem::transmute(saddr) };
        if sin.sin_family != libc::AF_INET as u16 {
            anyhow::bail!("communication domain not supported");
        };
        let addr: Ipv4Addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let port: u16 = u16::from_be(sin.sin_port);
        Ok(SocketAddr::new(ipv4_addr, port))
    }

    #[cfg(target_os = "windows")]
    /// Converts a [sockaddr] into a port number.
    pub fn sockaddr_to_socketaddrv4(saddr: SOCKADDR) -> Result<SocketAddr> {
        // Casting to SOCKADDR_IN
        let addr_in: SOCKADDR_IN = unsafe { std::mem::transmute(saddr) };

        if addr_in.sin_family != AF_INET_FAM {
            anyhow::bail!("communication domain not supported");
        };
        // Extracting IPv4 address and port
        let ipv4_addr = unsafe {
            Ipv4Addr::new(
                addr_in.sin_addr.S_un.S_un_b.s_b4,
                addr_in.sin_addr.S_un.S_un_b.s_b3,
                addr_in.sin_addr.S_un.S_un_b.s_b2,
                addr_in.sin_addr.S_un.S_un_b.s_b1,
            )
        };
        let port: u16 = u16::from_be(addr_in.sin_port);

        // Creating SocketAddrV4
        Ok(SocketAddr::new(IpAddr::V4(ipv4_addr), port))
    }

    fn create_outgoing_socket(&mut self, ip_addr: &SocketAddr) -> Result<QDesc> {
        timer!("proxy::create_outgoing_socket");
        // Create outgoing socket.
        let new_server_socket: QDesc = match self.catloop.socket(AF_INET, SOCK_STREAM, 0) {
            Ok(qd) => qd,
            Err(e) => {
                println!("ERROR: failed to create socket (error={:?})", e);
                anyhow::bail!("failed to create socket: {:?}", e.cause)
            },
        };

        // Connect to remote address.
        let qt = match self.catloop.connect(new_server_socket, self.remote_addr) {
            // Operation succeeded, register outgoing operation.
            Ok(qt) => qt,
            // Operation failed, close socket.
            Err(e) => {
                if let Err(e) = self.catloop.close(new_server_socket) {
                    // Failed to close socket, log error.
                    println!("ERROR: close failed (error={:?})", e);
                    println!("WARN: leaking socket descriptor (sockqd={:?})", new_server_socket);
                }
                anyhow::bail!("failed to connect socket: {:?}", e)
            },
        };

        // Wait for the accept
        match self.catloop.wait(qt, Some(Duration::from_secs(120))) {
            Ok(result) => {
                if result.qr_opcode != demi_opcode_t::DEMI_OPC_CONNECT {
                    println!("ERROR: unexpected opcode (opcode={:?})", result.qr_opcode);
                    anyhow::bail!("unexpected opcode: {:?}", result.qr_opcode)
                };
            },
            Err(e) => {
                println!("ERROR: failed to wait for accept (error={:?})", e);
                anyhow::bail!("failed to wait for accept: {:?}", e)
            },
        };

        self.outgoing_qds.insert(new_server_socket, false);
        self.outgoing_qds_map.insert(new_server_socket, ip_addr.clone());
        self.in_libos.insert_incoming_map(ip_addr.clone(), new_server_socket);

        Ok(new_server_socket)
    }

    /// Handles the completion of a `pop()` operation on an incoming flow.
    fn handle_incoming_pop(&mut self, qr: &demi_qresult_t) -> Result<()> {
        timer!("proxy::handle_incoming_pop");
        let incoming_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };

        // Get the incoming address
        let ip_addr = Self::sockaddr_to_socketaddrv4(unsafe { qr.qr_value.sga.sga_addr })?;

        let catloop_qd_opt: Option<&QDesc> = self.in_libos.get_incoming_map(&ip_addr);

        let catloop_qd: QDesc = match catloop_qd_opt {
            Some(catloop_qd) => *catloop_qd,
            None => {
                // Create outgoing socket.
                self.create_outgoing_socket(&ip_addr)?
            },
        };

        // Push SGA to concerned outgoing flow.
        let src: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = incoming_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(outgoing_sga) = self.catloop.sgaalloc(len) {
            // Copy.
            let dest: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);

            // Issue `push()` operation.
            if let Err(e) = self.issue_outgoing_push(catloop_qd, &outgoing_sga) {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
                return Err(e);
            }

            // Release outgoing SGA.
            if let Err(e) = self.catloop.sgafree(outgoing_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking outgoing sga");
                return Err(e.into());
            }
        }

        // Release incoming SGA.
        if let Err(e) = self.in_libos.sgafree(incoming_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking incoming sga");
            return Err(e.into());
        }

        // Pop more data from incoming flow.
        if let Err(e) = self.in_libos.issue_incoming_pop() {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
            return Err(e);
        }
        return Ok(());
    }

    /// Handles the completion of a `pop()` operation on an outgoing flow.
    fn handle_outgoing_pop(&mut self, qr: &demi_qresult_t) -> Result<()> {
        timer!("proxy::handle_outgoing_pop");
        let outgoing_sga: demi_sgarray_t = unsafe { qr.qr_value.sga };
        let catloop_qd: QDesc = qr.qr_qd.into();

        // Check if server aborted connection.
        if outgoing_sga.sga_segs[0].sgaseg_len == 0 {
            unimplemented!("server aborted connection");
        }

        // Push SGA to concerned incoming flow.
        let src: *mut libc::c_uchar = outgoing_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
        let len: usize = outgoing_sga.sga_segs[0].sgaseg_len as usize;
        if let Ok(incoming_sga) = self.in_libos.sgaalloc(len) {
            // Copy.
            let dest: *mut libc::c_uchar = incoming_sga.sga_segs[0].sgaseg_buf as *mut libc::c_uchar;
            Self::copy(src, dest, len);

            let client_address = match self.outgoing_qds_map.get(&catloop_qd) {
                Some(address) => address,
                None => {
                    return Err(anyhow::format_err!("No address found for incoming push"));
                },
            };

            // Issue `push()` operation.
            if let Err(e) = self
                .in_libos
                .issue_incoming_pushto(catloop_qd, &incoming_sga, *client_address)
            {
                // Failed to issue push operation, log error.
                println!("ERROR: push failed (error={:?})", e);
                return Err(e);
            }

            // Release incoming SGA.
            if let Err(e) = self.in_libos.sgafree(incoming_sga) {
                // Failed to release SGA, log error.
                println!("ERROR: sgafree failed (error={:?})", e);
                println!("WARN: leaking incoming sga");
                return Err(e.into());
            }
        }

        // Release outgoing SGA.
        if let Err(e) = self.catloop.sgafree(outgoing_sga) {
            // Failed to release SGA, log error.
            println!("ERROR: sgafree failed (error={:?})", e);
            println!("WARN: leaking outgoing sga");
            return Err(e.into());
        }

        // Pop data from outgoing flow.
        if let Err(e) = self.issue_outgoing_pop(catloop_qd) {
            // Failed to issue pop operation, log error.
            println!("ERROR: pop failed (error={:?})", e);
            return Err(e);
        }

        return Ok(());
    }

    /// Handles the completion of a `pushto()` operation on an incoming flow.
    /// This will issue a pop operation on the incoming connection, if none is inflight.
    fn handle_incoming_push(&mut self) -> Result<()> {
        self.in_libos.handle_incoming_push()
    }

    /// Handles the completion of a `push()` operation on an outgoing flow.
    /// This will issue a pop operation on the outgoing connection, if none is inflight.
    fn handle_outgoing_push(&mut self, qr: &demi_qresult_t) -> Result<()> {
        // Extract queue descriptor of outgoing connection.
        let outgoing_qd: QDesc = qr.qr_qd.into();

        // It is safe to call except() here, because `outgoing_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let has_inflight_pop: bool = self
            .outgoing_qds
            .get_mut(&outgoing_qd)
            .expect("queue descriptor should be registered")
            .to_owned();

        // Issue a pop operation if none is inflight.
        if !has_inflight_pop {
            println!("INFO: issuing outgoing pop (qd={:?})", outgoing_qd);
            if let Err(e) = self.issue_outgoing_pop(outgoing_qd) {
                // Failed to issue pop operation, log error.
                println!("ERROR: pop failed (error={:?})", e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Polls outgoing operations that are pending, with a timeout.
    ///
    /// If any pending operation completes when polling, its result value is
    /// returned. If the timeout expires before an operation completes, or an
    /// error is encountered, None is returned instead.
    fn poll_outgoing(&mut self, timeout: Option<Duration>) -> Option<demi_qresult_t> {
        timer!("proxy::poll_outgoing");
        match self.catloop.wait_any(&self.outgoing_qts, timeout) {
            Ok((idx, qr)) => {
                self.unregister_outgoing_operation(idx);
                Some(qr)
            },
            Err(e) if e.errno == libc::ETIMEDOUT => None,
            Err(e) => {
                println!("ERROR: unexpected error while polling outgoing queue (error={:?})", e);
                None
            },
        }
    }

    fn unregister_outgoing_operation(&mut self, index: usize) {
        let _: QToken = self.outgoing_qts.swap_remove(index);
    }

    /// Copies `len` bytes from `src` to `dest`.
    fn copy(src: *mut libc::c_uchar, dest: *mut libc::c_uchar, len: usize) {
        timer!("proxy::copy");
        let src: &mut [u8] = unsafe { slice::from_raw_parts_mut(src, len) };
        let dest: &mut [u8] = unsafe { slice::from_raw_parts_mut(dest, len) };
        dest.clone_from_slice(src);
    }

    /// Handles the completion of an unexpected operation.
    fn handle_unexpected(&mut self, op_name: &str, qr: &demi_qresult_t) -> Result<()> {
        let qd: QDesc = qr.qr_qd.into();
        let qt: QToken = qr.qr_qt.into();
        println!(
            "WARN: unexpected {} operation completed, ignoring (qd={:?}, qt={:?})",
            op_name, qd, qt
        );
        Ok(())
    }
}

impl Proxy for UdpTcpProxy {
    fn issue_next_op(&mut self) -> Result<()> {
        self.in_libos.issue_incoming_pop()
    }

    fn print_profile(&mut self, _clean: bool) -> Result<()> {
        Ok(())
    }

    fn non_blocking_poll(
        &mut self,
        timeout_incoming: Option<Duration>,
        timeout_outgoing: Option<Duration>,
    ) -> Result<()> {
        timer!("proxy::non_blocking_poll");
        // Poll incoming flows.
        if let Some(qr) = self.in_libos.poll_incoming(timeout_incoming) {
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_POP => self.handle_incoming_pop(&qr)?,
                demi_opcode_t::DEMI_OPC_PUSH => self.handle_incoming_push()?,
                demi_opcode_t::DEMI_OPC_FAILED => {
                    println!("ERROR: incoming operation failed (error={:?})", qr.qr_ret);
                    if let Err(e) = self.in_libos.issue_incoming_pop() {
                        println!("ERROR: failed to issue incoming pop (error={:?})", e);
                    }
                    anyhow::bail!("operation failed")
                },
                demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("incoming_accept", &qr)?,
                demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("incoming_invalid", &qr)?,
                demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("incoming_close", &qr)?,
                demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("incoming_connect", &qr)?,
            };
        }

        // Poll outgoing flows.
        if let Some(qr) = self.poll_outgoing(timeout_outgoing) {
            // Parse operation result.
            match qr.qr_opcode {
                demi_opcode_t::DEMI_OPC_POP => self.handle_outgoing_pop(&qr)?,
                demi_opcode_t::DEMI_OPC_PUSH => self.handle_outgoing_push(&qr)?,
                demi_opcode_t::DEMI_OPC_FAILED => {
                    println!("ERROR: outgoing operation failed (error={:?})", qr.qr_ret);
                    let catloop_qd: QDesc = qr.qr_qd.into();
                    if let Err(e) = self.issue_outgoing_pop(catloop_qd) {
                        println!("ERROR: failed to issue outgoing pop (error={:?})", e);
                    }
                    anyhow::bail!("operation failed")
                },
                demi_opcode_t::DEMI_OPC_ACCEPT => self.handle_unexpected("outgoing_accept", &qr)?,
                demi_opcode_t::DEMI_OPC_INVALID => self.handle_unexpected("outgoing_invalid", &qr)?,
                demi_opcode_t::DEMI_OPC_CLOSE => self.handle_unexpected("outgoing_close", &qr)?,
                demi_opcode_t::DEMI_OPC_CONNECT => self.handle_unexpected("outgoing_connect", &qr)?,
            };
        }

        Ok(())
    }

    fn run_eval(&mut self, _eval: EvalRequest) -> Result<()> {
        // Return not implemented error
        println!("Error: run_eval not implemented for UdpProxy");
        Err(anyhow::format_err!("Not implemented"))
    }
}

impl NetProxyManager {
    #[allow(dead_code)]
    pub fn new() -> (Self, Receiver<ProxyRequest>) {
        // Create a channel
        let (req_send, req_recv) = channel();

        (NetProxyManager { req_send }, req_recv)
    }

    fn get_proxy(proxy_req: &AddRequest, proxy_type: ProxyType) -> Result<Box<dyn Proxy>> {
        match proxy_type {
            ProxyType::Tcp => {
                match TcpProxy::new(
                    &proxy_req.vm_id,
                    proxy_req.local_address,
                    proxy_req.in_libos.clone(),
                    proxy_req.remote_addr,
                ) {
                    Ok(proxy) => Ok(Box::new(proxy)),
                    Err(e) => Err(e),
                }
            },
            ProxyType::Udp => {
                match UdpProxy::new(
                    &proxy_req.vm_id,
                    proxy_req.local_address,
                    proxy_req.in_libos.clone(),
                    proxy_req.remote_addr,
                ) {
                    Ok(proxy) => Ok(Box::new(proxy)),
                    Err(e) => Err(e),
                }
            },
            ProxyType::UdpTcp => {
                match UdpTcpProxy::new(
                    &proxy_req.vm_id,
                    proxy_req.local_address,
                    proxy_req.in_libos.clone(),
                    proxy_req.remote_addr,
                ) {
                    Ok(proxy) => Ok(Box::new(proxy)),
                    Err(e) => Err(e),
                }
            },
        }
    }
}

impl ProxyRun for NetProxyManager {
    fn run(event_receiver: Receiver<ProxyRequest>, proxy_type: ProxyType) -> Result<()> {
        // Map from device id (str) to TcpProxy
        // This is used to keep track of all the active proxies
        let mut proxy_map: HashMap<String, Box<dyn Proxy>> = HashMap::new();

        // Time interval for dumping logs and statistics.
        // Timeout for polling incoming operations.This was intentionally set to zero to force no waiting.
        let timeout_incoming: Option<Duration> = Some(Duration::from_secs(0));
        // Timeout for polling outgoing operations. This was intentionally set to zero to force no waiting.
        let timeout_outgoing: Option<Duration> = Some(Duration::from_secs(0));
        // Number of iterations after which the processing thread check for control plane ops
        let op_iteration_wait = 1000;

        // Initialize the shared memory for catloop
        #[cfg(feature = "virtio-shmem")]
        SharedMemory::initialize_static_mem_manager();

        let mut control_counter: usize = 0;
        for (_, proxy) in proxy_map.iter_mut() {
            match proxy.issue_next_op() {
                Ok(_) => {},
                Err(e) => {
                    // Log and panic
                    // \TODO Better error handling
                    println!("Error issuing next op: {:?}", e);
                    return Err(e);
                },
            }
        }
        loop {
            // \TODO: Only poll on active proxies
            for (_, proxy) in proxy_map.iter_mut() {
                match proxy.non_blocking_poll(timeout_incoming, timeout_outgoing) {
                    Ok(_) => {},
                    Err(e) => {
                        // Log and panic
                        // \TODO Better error handling
                        println!("Error polling proxy: {:?}", e);
                        continue;
                    },
                }
            }

            control_counter += 1;
            if control_counter == op_iteration_wait {
                timer!("proxy::control_op");
                control_counter = 0;
                match event_receiver.try_recv() {
                    Ok(request) => {
                        match request {
                            ProxyRequest::Add(proxy_req) => {
                                let mut new_proxy = match Self::get_proxy(&proxy_req, proxy_type.clone()) {
                                    Ok(proxy) => proxy,
                                    Err(e) => {
                                        // Log and panic
                                        // \TODO Better error handling
                                        println!("Error creating proxy: {:?}", e);
                                        continue;
                                    },
                                };

                                // \TODO move this out of the critical path, this can be an expensive operation
                                match new_proxy.issue_next_op() {
                                    Ok(_) => {},
                                    Err(e) => {
                                        // Log and panic
                                        // \TODO Better error handling
                                        println!("Error issuing accept: {:?}", e);
                                        continue;
                                    },
                                }
                                proxy_map.insert(proxy_req.vm_id, new_proxy);
                            },
                            ProxyRequest::Remove(vm_id) => {
                                proxy_map.remove(&vm_id);
                            },
                            ProxyRequest::RunEval(eval_req) => match proxy_map.get_mut(&eval_req.vm_id) {
                                Some(proxy) => proxy.run_eval(eval_req).unwrap(),
                                None => {
                                    println!("Error: could not find vm {:?}", &eval_req.vm_id);
                                    continue;
                                },
                            },
                            ProxyRequest::PrintProfile(p) => {
                                println!("Printing profile");
                                if p.clean {
                                    #[cfg(feature = "profiler")]
                                    profiler::reset();
                                    for (_, proxy) in proxy_map.iter_mut() {
                                        proxy.print_profile(true).unwrap();
                                    }
                                } else {
                                    #[cfg(feature = "profiler")]
                                    profiler::write(&mut std::io::stdout(), None).expect("failed to write to stdout");

                                    for (_, proxy) in proxy_map.iter_mut() {
                                        proxy.print_profile(false).unwrap();
                                    }
                                }
                            },
                        }
                    },
                    Err(_) => {
                        // \TODO: Better handle errors
                    },
                }
            }
        }
    }
}

impl Debug for NetProxyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetProxyManager")
    }
}

impl ProxyManager for NetProxyManager {
    fn add_proxy(
        &mut self,
        vm_id: &str,
        local_address: SocketAddr,
        in_libos: String,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let request = ProxyRequest::Add(AddRequest {
            vm_id: vm_id.to_string(),
            local_address,
            in_libos,
            remote_addr,
        });
        self.req_send.send(request)?;
        Ok(())
    }

    fn remove_proxy(&mut self, vm_id: &str) -> Result<()> {
        let request: ProxyRequest = ProxyRequest::Remove(vm_id.to_string());
        self.req_send.send(request)?;
        Ok(())
    }

    fn run_eval(
        &mut self,
        vm_id: &str,
        segment_name: &str,
        data_size: u32,
        iterations: u32,
        segment_size: u32,
    ) -> Result<()> {
        let request: ProxyRequest = ProxyRequest::RunEval(EvalRequest {
            vm_id: vm_id.to_string(),
            segment_name: segment_name.to_string(),
            data_size,
            iterations,
            segment_size,
        });
        self.req_send.send(request)?;
        Ok(())
    }

    fn print_profile(&self, clean: bool) -> Result<()> {
        let request: ProxyRequest = ProxyRequest::PrintProfile(ProfileRequest { clean });
        self.req_send.send(request)?;
        Ok(())
    }
}
