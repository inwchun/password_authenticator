use packed_struct;

#[macro_use] extern crate packed_struct_codegen;
#[macro_use] mod logger;
#[macro_use] extern crate lazy_static;

mod communication;
mod tools;
mod test;

use std::net::{TcpListener, TcpStream};
use std::error::{Error};
use crate::communication::usbip::bindings as c;
use crate::communication::usbip;
use crate::communication::eventloop;
use crate::tools::protocol::{prove, setup};

use crate::test::{latencytest};

// Run server for USB IP
fn main() {

    // latencytest();

    // usbip port
    println!("RUNNING AUTHENTICATOR");
    let listener = TcpListener::bind("127.0.0.1:3240").unwrap();
    for s in listener.incoming() {
        let mut stream = s.unwrap();
        stream.set_nodelay(true).unwrap();
        let (version, code, status) = usbip::read_op_common(&mut stream).unwrap();
        match (version, code as u32, status) {
            (usbip::USBIP_VERSION, c::OP_REQ_DEVLIST, 0) => {
                println!("OP_REQ_DEVLIST");
                usbip::write_op_rep_devlist (&mut stream).unwrap();
                stream.shutdown(std::net::Shutdown::Both).unwrap()
            },
            (usbip::USBIP_VERSION, c::OP_REQ_IMPORT, 0) => {
                let busid = usbip::read_busid(&mut stream).unwrap();
                if busid != "1-1" {
                    panic!("Invalid busid: {}", busid)
                }
                usbip::write_op_rep_import(&mut stream).unwrap();
                let mut dev = usbip::Device::new();
                let mut el = eventloop::EventLoop::new(&mut dev);
                usbip::Device::init_callbacks(&mut el);
                el.handle_commands(&mut stream).unwrap()
            },
            _ => panic!("Unsupported operation")
        }
    };
}
