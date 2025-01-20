use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    num::Wrapping,
    time::Duration,
};

use crate::{
    pdu::{self, Pdu},
    Error, MessageType, Oid, Result, Value, Version, BUFFER_SIZE,
};

#[cfg(feature = "v3")]
use crate::v3;

/// Synchronous SNMP client
pub struct SyncSession {
    version: Version,
    socket: UdpSocket,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    send_pdu: pdu::Buf,
    recv_buf: [u8; BUFFER_SIZE],
    #[cfg(feature = "v3")]
    security: Option<v3::Security>,
}

impl SyncSession {
    pub fn new_v1<SA>(
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(
            Version::V1,
            destination,
            community,
            timeout,
            starting_req_id,
        )
    }

    pub fn new_v2c<SA>(
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        Self::new(
            Version::V2C,
            destination,
            community,
            timeout,
            starting_req_id,
        )
    }

    #[cfg(feature = "v3")]
    pub fn new_v3<SA>(
        destination: SA,
        timeout: Option<Duration>,
        starting_req_id: i32,
        security: v3::Security,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let mut session = Self::new(Version::V3, destination, &[], timeout, starting_req_id)?;
        session.community = security.username.clone();
        session.security = Some(security);
        Ok(session)
    }

    fn new<SA>(
        version: Version,
        destination: SA,
        community: &[u8],
        timeout: Option<Duration>,
        starting_req_id: i32,
    ) -> io::Result<Self>
    where
        SA: ToSocketAddrs,
    {
        let socket = match destination.to_socket_addrs()?.next() {
            Some(SocketAddr::V4(_)) => UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), 0))?,
            Some(SocketAddr::V6(_)) => UdpSocket::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0))?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No address found",
                ))
            }
        };
        socket.set_read_timeout(timeout)?;
        socket.set_write_timeout(timeout)?;
        socket.connect(destination)?;
        Ok(Self {
            version,
            socket,
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            send_pdu: pdu::Buf::default(),
            recv_buf: [0; BUFFER_SIZE],
            #[cfg(feature = "v3")]
            security: None,
        })
    }

    #[cfg(feature = "v3")]
    pub fn with_security(mut self, mut security: v3::Security) -> Result<Self> {
        security.username = self.community.clone();
        if !security.authentication_password.is_empty()
            || !security.authoritative_state.engine_id.is_empty()
        {
            security.update_key()?;
        }
        self.security = Some(security);
        Ok(self)
    }

    fn send_and_recv<'a>(
        socket: &UdpSocket,
        pdu: &pdu::Buf,
        out: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        let _pdu_len = socket.send(pdu).map_err(|e| Error::Send(e.kind()))?;
        let len = socket.recv(out).map_err(|e| Error::Receive(e.kind()))?;
        Ok(&out[..len])
    }

    #[cfg(not(feature = "v3"))]
    pub fn init(&mut self) -> Result<()> {
        Ok(())
    }

    #[cfg(feature = "v3")]
    pub fn init(&mut self) -> Result<()> {
        if let Some(ref mut security) = self.security {
            security.reset_engine_id();
            security.reset_engine_counters();
            // send a request to get the engine id
            let req_id = self.req_id.0;
            v3::build_init(req_id, &mut self.send_pdu);
            self.req_id += Wrapping(1);
            if let Err(e) = Pdu::from_bytes_inner(
                Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf)?,
                Some(security),
            ) {
                if e != Error::AuthUpdated {
                    return Err(e);
                }
            }
            if security.need_init() {
                return Err(Error::AuthFailure(v3::AuthErrorKind::NotAuthenticated));
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "v3"))]
    #[allow(clippy::unused_self)]
    fn prepare(&mut self) {}

    #[cfg(feature = "v3")]
    fn prepare(&mut self) {
        if let Some(ref mut security) = self.security {
            security.correct_authoritative_engine_time();
        }
    }

    pub fn get(&mut self, oid: &Oid) -> Result<Pdu> {
        self.prepare();
        let req_id = self.req_id.0;
        pdu::build_get(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf)?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn getnext(&mut self, oid: &Oid) -> Result<Pdu> {
        self.prepare();
        let req_id = self.req_id.0;
        pdu::build_getnext(
            self.version,
            self.community.as_slice(),
            req_id,
            oid,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf)?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn getbulk(
        &mut self,
        oids: &[&Oid],
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Pdu> {
        self.prepare();
        let req_id = self.req_id.0;
        pdu::build_getbulk(
            self.version,
            self.community.as_slice(),
            req_id,
            oids,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf)?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        self.req_id += Wrapping(1);
        println!("Error idx : {:?}", resp.error_index);
        println!("Error status : {:?}", resp.error_status);
        resp.clone().varbinds.for_each(|v| print!("Varbind: {:?}", v));
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }

    pub fn set(&mut self, values: &[(&Oid, Value)]) -> Result<Pdu> {
        self.prepare();
        let req_id = self.req_id.0;
        pdu::build_set(
            self.version,
            self.community.as_slice(),
            req_id,
            values,
            &mut self.send_pdu,
            #[cfg(feature = "v3")]
            self.security.as_ref(),
        )?;
        let resp = Pdu::from_bytes_inner(
            Self::send_and_recv(&self.socket, &self.send_pdu, &mut self.recv_buf)?,
            #[cfg(feature = "v3")]
            self.security.as_mut(),
        )?;
        self.req_id += Wrapping(1);
        resp.validate(MessageType::Response, req_id, &self.community)?;
        Ok(resp)
    }
}
