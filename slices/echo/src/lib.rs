use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
struct SliceAlloc {
    pub offset: u32,
    pub length: u32,
}

impl From<u64> for SliceAlloc {
    fn from(raw: u64) -> Self {
        let [o1, o2, o3, o4, l1, l2, l3, l4] = raw.to_le_bytes();
        let offset = u32::from_le_bytes([o1, o2, o3, o4]);
        let length = u32::from_le_bytes([l1, l2, l3, l4]);
        Self { offset, length }
    }
}

impl From<SliceAlloc> for u64 {
    fn from(alloc: SliceAlloc) -> Self {
        let [o1, o2, o3, o4] = alloc.offset.to_le_bytes();
        let [l1, l2, l3, l4] = alloc.length.to_le_bytes();
        u64::from_le_bytes([o1, o2, o3, o4, l1, l2, l3, l4])
    }
}

impl From<&[u8]> for SliceAlloc {
    fn from(s: &[u8]) -> Self {
        let offset = s.as_ptr() as _;
        let length = s.len() as _;
        Self { offset, length }
    }
}

impl From<&str> for SliceAlloc {
    fn from(s: &str) -> Self {
        s.as_bytes().into()
    }
}

impl From<SliceAlloc> for &[u8] {
    fn from(alloc: SliceAlloc) -> Self {
        unsafe { std::slice::from_raw_parts(alloc.offset as _, alloc.length as _) }
    }
}

impl From<SliceAlloc> for String {
    fn from(alloc: SliceAlloc) -> Self {
        String::from_utf8_lossy(alloc.into()).to_string()
    }
}

impl From<SliceAlloc> for std::alloc::Layout {
    fn from(alloc: SliceAlloc) -> Self {
        Self::from_size_align(alloc.length as usize, 1).unwrap()
    }
}

impl From<SliceAlloc> for *mut u8 {
    fn from(alloc: SliceAlloc) -> Self {
        alloc.offset as usize as _
    }
}

impl From<(*mut u8, u32)> for SliceAlloc {
    fn from(p: (*mut u8, u32)) -> Self {
        Self {
            offset: p.0 as usize as _,
            length: p.1,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RequestMeta {
    pub method: String,
    pub uri: String,
}

#[derive(Debug, Serialize)]
struct ResponseMeta<'m> {
    pub status: u16,
    pub headers: Vec<(&'m [u8], &'m [u8])>,
}

extern "C" {
    fn print_log(level: log::Level, alloc: u64);

    fn size_meta() -> u32;
    fn read_meta(alloc: u64) -> i32;
    fn read_body(alloc: u64) -> i32;

    fn write_meta(alloc: u64) -> i32;
    fn write_body(alloc: u64) -> i32;
}

struct Logger;
static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let message = format!("{}", record.args());
        unsafe {
            print_log(record.level(), SliceAlloc::from(message.as_str()).into());
        }
    }

    fn flush(&self) {}
}

#[export_name = "slice_start"]
pub fn main() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Trace))
        .unwrap();

    log::info!("hello world");
    log::debug!("req meta size: {}", unsafe { size_meta() });

    let mut meta_raw = vec![0; unsafe { size_meta() } as _];
    let meta_alloc = SliceAlloc::from(meta_raw.as_slice());
    let meta_read = unsafe { read_meta(meta_alloc.into()) };
    if meta_read < 0 {
        log::error!("error reading meta!");
        return;
    }
    meta_raw.truncate(meta_read as _);

    log::debug!("raw meta: {}", String::from_utf8_lossy(&meta_raw));
    let req: RequestMeta = serde_cbor::from_slice(&meta_raw).unwrap();

    log::debug!("req meta: {:?}", req);

    let res = serde_cbor::to_vec(&ResponseMeta {
        status: 204,
        headers: vec![(b"X-Request-URI", req.uri.as_bytes())],
    })
    .unwrap();

    log::debug!("res meta: {:?}", res);
    let res_alloc = SliceAlloc::from(res.as_slice());
    let written = unsafe { write_meta(res_alloc.into()) };
    if written < 0 {
        log::error!("error writing meta!");
    }
}
