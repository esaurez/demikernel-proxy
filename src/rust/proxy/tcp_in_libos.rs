// Copyright (c) Microsoft Corporation.

//======================================================================================================================
// Imports
//======================================================================================================================
use ::anyhow::Result;

use ::demikernel::{
    demi_sgarray_t,
    runtime::types::demi_qresult_t,
    timer,
    LibOS,
    QDesc,
    QToken,
};

use ::std::{
    collections::HashMap,
    time::Duration,
};
use std::net::SocketAddr;

use crate::constants::{
    AF_INET,
    SOCK_STREAM,
};

pub struct IncomingTcpLibos {
    /// LibOS that handles incoming flow.
    in_libos: LibOS,
    /// Socket for accepting incoming connections.
    local_socket: QDesc,
    /// Queue descriptors of incoming connections.
    incoming_qds: HashMap<QDesc, bool>,
    /// Maps a queue descriptor of an incoming connection to its respective outgoing connection.
    incoming_qds_map: HashMap<QDesc, QDesc>,
    /// Incoming operations that are pending.
    incoming_qts: Vec<QToken>,
    /// Maps a pending incoming operation to its respective queue descriptor.
    incoming_qts_map: HashMap<QToken, QDesc>,
}

impl IncomingTcpLibos {
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
            incoming_qds: HashMap::new(),
            incoming_qds_map: HashMap::new(),
            incoming_qts: Vec::with_capacity(Self::INCOMING_LENGTH),
            incoming_qts_map: HashMap::new(),
        })
    }

    /// Issues a `push()` operation in an incoming flow.
    /// This function fails if the underlying `push()` operation fails.
    pub fn issue_incoming_push(&mut self, qd: QDesc, sga: &demi_sgarray_t) -> Result<()> {
        timer!("proxy::issue_incoming_push");
        let qt: QToken = self.in_libos.push(qd, &sga)?;

        // It is safe to call except() here, because we just issued the `push()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_incoming_operation(qd, qt)
            .expect("incoming push() operration is already registered");

        Ok(())
    }

    /// Setups local socket.
    fn setup_local_socket(in_libos: &mut LibOS, local_addr: SocketAddr) -> Result<QDesc> {
        // Create local socket.
        let local_socket: QDesc = match in_libos.socket(AF_INET, SOCK_STREAM, 0) {
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

        // Enable socket to accept incoming connections.
        if let Err(e) = in_libos.listen(local_socket, 16) {
            // Listen failed, close socket.
            if let Err(e) = in_libos.close(local_socket) {
                // Close failed, log error.
                println!("ERROR: close failed (error={:?})", e);
                println!("WARN: leaking socket descriptor (sockqd={:?})", local_socket);
            }
            anyhow::bail!("listen failed: {:?}", e.cause)
        }

        Ok(local_socket)
    }

    /// Issues an `accept()`operation.
    /// This function fails if the underlying `accept()` operation fails.
    pub fn issue_accept(&mut self) -> Result<()> {
        timer!("proxy::issue_accept");
        let qt: QToken = self.in_libos.accept(self.local_socket)?;
        self.register_incoming_operation(self.local_socket, qt)?;
        Ok(())
    }

    /// Registers an incoming operation that is waiting for completion (pending).
    /// This function fails if the operation is already registered in the table of pending incoming operations.
    fn register_incoming_operation(&mut self, qd: QDesc, qt: QToken) -> Result<()> {
        timer!("proxy:register_incoming");
        if self.incoming_qts_map.insert(qt, qd).is_some() {
            anyhow::bail!("incoming operation is already registered (qt={:?})", qt);
        }
        self.incoming_qts.push(qt);
        Ok(())
    }

    pub fn get_incoming_qd(&mut self, outgoing_qd: QDesc) -> QDesc {
        // It is safe to call except() here, because `catloop_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let in_libos_qd: QDesc = *self
            .incoming_qds_map
            .get(&outgoing_qd)
            .expect("queue descriptor should be registered");
        in_libos_qd
    }

    /// Issues a `pop()` operation in an incoming flow.
    /// This function fails if the underlying `pop()` operation fails.
    pub fn issue_incoming_pop(&mut self, qd: QDesc) -> Result<()> {
        timer!("proxy::issue_incoming_pop");

        let qt: QToken = self.in_libos.pop(qd, None)?;

        // It is safe to call except() here, because we just issued the `pop()` operation,
        // queue tokens are unique, and thus the operation is ensured to not be registered.
        self.register_incoming_operation(qd, qt)
            .expect("incoming pop() operration is already registered");

        // Set the flag to indicate that this flow has an inflight `pop()` operation.
        // It is safe to call except() here, because `qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let in_libos_inflight_pop: &mut bool = self
            .incoming_qds
            .get_mut(&qd)
            .expect("queue descriptor should be registered");
        *in_libos_inflight_pop = true;

        Ok(())
    }

    /// Handles the completion of a `push()` operation on an incoming flow.
    /// This will issue a pop operation on the incoming connection, if none is inflight.
    pub fn handle_incoming_push(&mut self, qr: &demi_qresult_t) {
        timer!("proxy::handle_incoming_push");
        // Extract queue descriptor of incoming connection.
        let incoming_qd: QDesc = qr.qr_qd.into();

        // It is safe to call except() here, because `incoming_qd` is ensured to be in the table of queue descriptors.
        // All queue descriptors are registered when connection is established.
        let has_inflight_pop: bool = self
            .incoming_qds
            .get_mut(&incoming_qd)
            .expect("queue descriptor should be registered")
            .to_owned();

        // Issue a pop operation if none is inflight.
        if !has_inflight_pop {
            unreachable!("should have an incoming pop, but it hasn't (qd={:?})", incoming_qd);
        }
    }

    // This function closees the connection and returns the internal socket descriptor
    pub fn close(&mut self, in_libos_socket: QDesc) -> Result<()> {
        match self.in_libos.close(in_libos_socket) {
            Ok(_) => {
                println!(
                    "handle cancellation of tokens (in_libos_socket={:?})",
                    self.local_socket
                );
                self.incoming_qds.remove(&in_libos_socket).unwrap();
                let qts_drained: HashMap<QToken, QDesc> = self
                    .incoming_qts_map
                    .extract_if(|_k, v| v == &in_libos_socket)
                    .collect();
                let _: Vec<_> = self.incoming_qts.extract_if(|x| qts_drained.contains_key(x)).collect();
            },
            Err(e) => {
                println!("ERROR: failed to close socket (error={:?})", e);
                anyhow::bail!("failed to close socket (error={:?})", e)
            },
        };

        Ok(())
    }

    fn unregister_incoming_operation(&mut self, index: usize) {
        let qt: QToken = self.incoming_qts.remove(index);
        // It is safe to call except() here, because `qt` is ensured to be in the table of pending operations.
        // All queue tokens are registered in the table of pending operations when they are issued.
        self.incoming_qts_map
            .remove(&qt)
            .expect("queue token should be registered");
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
                timer!("proxy::poll_incoming::get_result");
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

    pub fn insert_qds(&mut self, new_server_socket: QDesc, new_client_socket: QDesc) {
        self.incoming_qds.insert(new_client_socket, false);
        self.incoming_qds_map.insert(new_server_socket, new_client_socket);
    }

    pub fn remove_qds_map(&mut self, outgoing_qd: &QDesc) -> Result<()> {
        match self.incoming_qds_map.remove(outgoing_qd) {
            Some(_) => Ok(()),
            None => {
                println!("ERROR: failed to remove queue descriptor (qd={:?})", outgoing_qd);
                anyhow::bail!("failed to remove queue descriptor (qd={:?})", outgoing_qd)
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
}
