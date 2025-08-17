use bytes::Bytes;
use sib::network::http::{
    server::HFactory,
    session::{HService, Session},
    util::Status,
};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Precomputed static bodies (zero alloc per request)
const PLAIN_BODY: &[u8] = b"Hello, World!";
const PLAIN_CL: &str = "13"; // PLAIN_BODY.len()

const JSON_BODY: &[u8] = br#"{"message":"Hello, World!"}"#;
const JSON_CL: &str = "27"; // JSON_BODY.len()

struct Server;

impl HService for Server {
    #[inline]
    fn call<S: Session>(&mut self, session: &mut S) -> std::io::Result<()> {
        if matches!(session.req_path(), Some("/json")) {
            session
                .status_code(Status::Ok)
                .header_str("Content-Type", "application/json")?
                .header_str("Content-Length", JSON_CL)?
                .body(&Bytes::from_static(JSON_BODY))
                .eom();
            return Ok(());
        }
        session
            .status_code(Status::Ok)
            .header_str("Content-Type", "text/plain")?
            .header_str("Content-Length", PLAIN_CL)?
            .body(&Bytes::from_static(PLAIN_BODY))
            .eom();
        Ok(())
    }
}

impl HFactory for Server {
    type Service = Server;

    #[inline]
    fn service(&self, _id: usize) -> Server {
        Server
    }
}

fn main() {
    let cpus = num_cpus::get();
    println!("CPU cores: {cpus}");
    sib::set_num_workers(cpus);

    let addr = "0.0.0.0:8080";
    println!("Listening {addr}");

    Server
        .start_h1(addr, 0)
        .expect("h1 server failed to start")
        .join()
        .expect("h1 server thread join failed");
}
