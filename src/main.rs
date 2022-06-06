use packed_struct;
use serde_cbor;

#[macro_use] extern crate packed_struct_codegen;
#[macro_use] mod macros;
#[macro_use] extern crate lazy_static;

mod usbip;
mod hid;
mod ctaphid;
mod eventloop;
mod crypto;
mod prompt;

use std::net::{TcpListener, TcpStream};
use std::error::{Error};
use usbip::bindings as c;

// Run server for USB IP
fn main() {
    let listener = TcpListener::bind("127.0.0.1:3240").unwrap();
    println!("HanPass Authenticator Server Running.");
    for s in listener.incoming() {
        println!("New connection {:?}\n", s);
        handle_stream(&mut s.unwrap()).unwrap();
    };
}

fn handle_stream (stream: &mut TcpStream)
                  -> Result<(), Box<dyn Error>> {
    stream.set_nodelay(true)?;
    let (version, code, status) = usbip::read_op_common(stream)?;
    match (version, code as u32, status) {
        (usbip::USBIP_VERSION, c::OP_REQ_DEVLIST, 0) => {
            println!("OP_REQ_DEVLIST");
            usbip::write_op_rep_devlist (stream)?;
            stream.shutdown(std::net::Shutdown::Both)?
        },
        (usbip::USBIP_VERSION, c::OP_REQ_IMPORT, 0) => {
            println!("OP_REQ_IMPORT");
            let busid = usbip::read_busid(stream)?;
            println!("busid: {}", busid);
            if busid != "1-1" {
                panic!("Invalid busid: {}", busid)
            }
            usbip::write_op_rep_import (stream)?;
            println!("import request busid {} complete", busid);
            handle_commands(stream)?
        },
        _ =>
            panic!("Unsupported packet: \
                    version: 0x{:x} code: 0x{:x} status: 0x{:x}",
                   version, code, status),
    }
    Ok(())
}

fn handle_commands (stream: &mut TcpStream)
                    -> Result<(), Box<dyn Error>> {
    let mut dev = usbip::Device::new();
    let mut el = eventloop::EventLoop::new(&mut dev);
    usbip::Device::init_callbacks(&mut el);
    el.handle_commands(stream)
}
