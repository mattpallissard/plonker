use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::PerfBufferBuilder;
use std::mem::MaybeUninit;
use std::time::Duration;
//use plain::Plain;
//use time::macros::format_description;
//use time::OffsetDateTime;
//use std::net::{SocketAddr, SocketAddrV6};
use epoll::{self, Event, Events};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddrV6;
//use std::os::fd::FromRawFd;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

const MAX_EVENTS: usize = 32;
const MAX_THREADS: usize = 4;

#[derive(Clone)]
struct PortInfo {
    port: u16,
    server_fd: i32,
}

struct ThreadData {
    sockets: Vec<Socket>,
}

static EXITING: AtomicBool = AtomicBool::new(false);

mod tcpstates {
    include!("./bpf/tcpstates.skel.rs");
}
use tcpstates::*;

#[derive(Debug, Parser)]
struct Command {
    /// Trace latency higher than this value
    #[arg(default_value = "10000")]
    latency: u64,
    /// Process PID to trace
    #[arg(default_value = "0")]
    pid: i32,
    /// Thread TID to trace
    #[arg(default_value = "0")]
    tid: i32,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn bind_port(port_no: u16) -> Result<i32> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;

    let addr = SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port_no, 0, 0);
    socket.bind(&addr.into())?;
    socket.listen(3)?;

    Ok(socket.as_raw_fd())
}

struct PortHandler {
    epoll_fd: i32,
    events: Vec<Event>,
    sockets: Vec<Socket>,
}

impl PortHandler {
    fn new(ports: Vec<Socket>) -> io::Result<Self> {
        println!("Creating epoll instance");
        let epoll_fd = epoll::create(false)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create epoll: {}", e)))?;

        println!("Epoll fd: {}", epoll_fd);

        let handler = PortHandler {
            epoll_fd,
            events: vec![Event::new(Events::empty(), 0); MAX_EVENTS],
            sockets: ports,
        };

        // Add each socket to epoll
        for socket in &handler.sockets {
            let fd = socket.as_raw_fd();
            println!("Adding fd {} for socket", fd);

            epoll::ctl(
                handler.epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                fd,
                Event::new(Events::EPOLLIN, fd as u64),
            )
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("Failed to add fd {} to epoll: {}", fd, e),
                )
            })?;
        }

        Ok(handler)
    }
    fn handle_events(&mut self, timeout_ms: i32) -> io::Result<()> {
        match epoll::wait(self.epoll_fd, timeout_ms, &mut self.events) {
            Ok(num_events) => {
                for event in self.events.iter().take(num_events) {
                    self.accept_connection(event.data as i32)?;
                }
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
            Err(e) => Err(Error::new(
                ErrorKind::Other,
                format!("Epoll wait error: {}", e),
            )),
        }
    }

    fn accept_connection(&self, server_fd: i32) -> io::Result<()> {
        unsafe {
            let mut addr: libc::sockaddr = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;

            let client_fd = libc::accept4(server_fd, &mut addr, &mut len, libc::SOCK_CLOEXEC);

            if client_fd >= 0 {
                libc::close(client_fd);
                Ok(())
            } else {
                Err(Error::last_os_error())
            }
        }
    }
}

impl Drop for PortHandler {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.epoll_fd);
        }
    }
}

fn handle_ports(thread_data: ThreadData) {
    println!(
        "Starting port handler with {} ports",
        thread_data.sockets.len()
    );

    let mut handler = match PortHandler::new(thread_data.sockets) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to create port handler: {}", e);
            return;
        }
    };

    while !EXITING.load(Ordering::Relaxed) {
        if let Err(e) = handler.handle_events(10) {
            eprintln!("Error handling events: {}", e);
            break;
        }
    }
}

fn handle_event(_cpu: i32, _data: &[u8]) {
    // Parse event data and print JSON output
    // You'll need to implement the event structure parsing here
    println!("Event received");
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    // Set up signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        EXITING.store(true, Ordering::SeqCst);
    })?;

    // Set up BPF
    let mut skel_builder = TcpstatesSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Set up ports for binding
    let mut ports = Vec::new();
    for port in 1337..=1338 {
        println!("{}", port);
        if let Ok(server_fd) = bind_port(port) {
            ports.push(PortInfo { port, server_fd });
        }
    }

    // Distribute ports across threads
    let ports_per_thread = (ports.len() + MAX_THREADS - 1) / MAX_THREADS;
    // In your main function where you distribute ports to threads
    let mut handles = vec![];
    for chunk in ports.chunks(ports_per_thread) {
        // Create new sockets for this thread
        let thread_sockets: Vec<Socket> = chunk
            .iter()
            .map(|port_info| {
                let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).unwrap();
                socket.set_reuse_address(true).unwrap();
                socket.set_only_v6(false).unwrap();

                let addr = SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port_info.port, 0, 0);
                socket.bind(&addr.into()).unwrap();
                socket.listen(3).unwrap();

                socket
            })
            .collect();

        let thread_data = ThreadData {
            sockets: thread_sockets,
        };

        let handle = thread::spawn(move || {
            handle_ports(thread_data);
        });

        handles.push(handle);
    }

    // Set up BPF monitoring
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let perf = PerfBufferBuilder::new(&skel.maps.events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .pages(1024)
        .build()?;

    while running.load(Ordering::SeqCst) {
        match perf.poll(Duration::from_millis(0)) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error polling: {}", e);
            }
        }
    }

    // Clean up
    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
