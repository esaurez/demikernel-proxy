// Copyright (c) Microsoft Corporation.

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;

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
use demikernel::demikernel::libos;

use ::std::{
    collections::HashMap,
    slice,
    time::Duration,
};
use std::net::SocketAddr;

use crate::constants::{
    AF_INET,
    SOCK_DGRAM,
};

pub struct IncomingUdpLibos {
    /// LibOS that handles incoming flow.
    in_libos: LibOS,
    /// Socket for accepting incoming connections.
    local_socket: QDesc,
    /// Incoming operations that are pending.
    incoming_qts: Vec<QToken>,
    /// Maps an incoming address to its respective outgoing socket
    incoming_client_map: HashMap<SocketAddr, QDesc>,
}

impl IncomingUdpLibos {
    /// Expected length for the array of pending incoming operations.
    /// It controls the pre-allocated size of the array.
    /// Change this value accordingly so as to avoid allocations on the datapath.
    const INCOMING_LENGTH: usize = 1024;

    pub fn new(libos_name: String, local_addr: SocketAddr) -> Result<Self> {
        // Instantiate LibOS for handling incoming flows.
        let mut in_libos: LibOS = match LibOS::new(libos_name.into()) {
            Ok(libos) => libos,
            Err(e) => {
                println!("failed to initialize libos (error={:?})", e);
                anyhow::bail!("failed to initialize libos (error={:?})", e)
            },
        };

        // Setup local socket.
        let local_socket: QDesc = Self::setup_local_socket(&mut in_libos, local_addr)?;

        Ok(Self {
            in_libos,
            local_socket,
            incoming_qts: Vec::with_capacity(Self::INCOMING_LENGTH),
            incoming_client_map: HashMap::default(),
        })
    }

    /// Registers an incoming operation that is waiting for completion (pending).
    pub fn register_incoming_operation(&mut self, qt: QToken) {
        self.incoming_qts.push(qt);
    }

    pub fn unregister_incoming_operation(&mut self, index: usize) {
        let _: QToken = self.incoming_qts.swap_remove(index);
    }

    /// Issues a `pushto()` operation in an incoming flow.
    /// This function fails if the underlying `push()` operation fails.
    pub fn issue_incoming_pushto(&mut self, qd: QDesc, sga: &demi_sgarray_t, to: SocketAddr) -> Result<()> {
        timer!("proxy::issue_incoming_push");

        let qt: QToken = self.in_libos.pushto(qd, &sga, to)?;

        // It is safe to call except() here, because we just issued the `push()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_incoming_operation(qt);

        Ok(())
    }

    pub fn handle_incoming_push(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn insert_incoming_map(&mut self, ip_address: SocketAddr, outgoing_qd: QDesc) {
        self.incoming_client_map.insert(ip_address, outgoing_qd);
    }

    pub fn get_incoming_map(&mut self, ip_address: &SocketAddr) -> Option<&QDesc> {
        self.incoming_client_map.get(ip_address)
    }

    /// Setups local socket.
    fn setup_local_socket(in_libos: &mut LibOS, local_addr: SocketAddr) -> Result<QDesc> {
        // Create local socket.
        let local_socket: QDesc = match in_libos.socket(AF_INET, SOCK_DGRAM, 0) {
            Ok(qd) => qd,
            Err(e) => {
                println!("ERROR: failed to create socket (error={:?})", e);
                anyhow::bail!("failed to create socket: {:?}", e.cause)
            },
        };

        // Bind socket to local address.
        if let Err(e) = in_libos.bind(local_socket, local_addr) {
            // Bind failed, close socket.
            if let Err(e) = in_libos.close(local_socket) {
                // Close failed, log error.
                println!("ERROR: close failed (error={:?})", e);
                println!("WARN: leaking socket descriptor (sockqd={:?})", local_socket);
            }
            anyhow::bail!("bind failed: {:?}", e.cause)
        };

        Ok(local_socket)
    }

    /// This function fails if the underlying `pop()` operation fails.
    pub fn issue_incoming_pop(&mut self) -> Result<()> {
        timer!("proxy::issue_incoming_pop");
        let qt: QToken = self.in_libos.pop(self.local_socket, None)?;

        // It is safe to call except() here, because we just issued the `pop()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_incoming_operation(qt);
        Ok(())
    }

    /// Polls incoming operations that are pending, with a timeout.
    ///
    /// If any pending operation completes when polling, its result value is
    /// returned. If the timeout expires before an operation completes, or an
    /// error is encountered, None is returned instead.
    pub fn poll_incoming(&mut self, timeout: Option<Duration>) -> Option<demi_qresult_t> {
        timer!("proxy::poll_incoming");
        match self.in_libos.wait_any(&self.incoming_qts, timeout) {
            Ok((idx, qr)) => {
                self.unregister_incoming_operation(idx);
                Some(qr)
            },
            Err(e) if e.errno == libc::ETIMEDOUT => None,
            Err(e) => {
                println!("ERROR: unexpected error while polling incoming queue (error={:?})", e);
                None
            },
        }
    }

    pub fn sgaalloc(&mut self, size: usize) -> Result<demi_sgarray_t> {
        match self.in_libos.sgaalloc(size) {
            Ok(ptr) => Ok(ptr),
            Err(e) => {
                anyhow::bail!("failed to allocate memory (error={:?})", e);
            },
        }
    }

    pub fn sgafree(&mut self, sga: demi_sgarray_t) -> Result<()> {
        match self.in_libos.sgafree(sga) {
            Ok(_) => Ok(()),
            Err(e) => {
                println!("ERROR: failed to free memory (error={:?})", e);
                anyhow::bail!("failed to free memory (error={:?})", e);
            },
        }
    }

    // This function closees the connection and returns the internal socket descriptor
    pub fn close(&mut self) -> Result<()> {
        match self.in_libos.close(self.local_socket) {
            Ok(_) => {
                println!(
                    "handle cancellation of tokens (in_libos_socket={:?})",
                    self.local_socket
                );
            },
            Err(e) => {
                println!("ERROR: failed to close socket (error={:?})", e);
                anyhow::bail!("failed to close socket (error={:?})", e)
            },
        };

        Ok(())
    }
}
