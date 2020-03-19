use num_derive::{FromPrimitive, ToPrimitive};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[no_mangle]
pub unsafe fn alloc(size: i32, align: i32) -> (i32, i32, i32) {
    use std::alloc::{GlobalAlloc, Layout};

    let layout = Layout::from_size_align(size as usize, align as usize).unwrap();
    let ptr = ALLOC.alloc(layout);

    (0, ptr as usize as i32, size)
}

#[no_mangle]
pub unsafe fn dealloc(_memory: i32, offset: i32, length: i32) {
    use std::alloc::{GlobalAlloc, Layout};

    let layout = Layout::from_size_align(length as usize, 1).unwrap();
    let ptr = offset as usize as *mut u8;
    ALLOC.dealloc(ptr, layout);
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum SliceError {
    None = 0,
    Generic = 1,
    Alloc = 2,
    NotImplemented = 51,

    InvalidResponse = 100,
    StatusOutOfBounds = 101,

    Unknown = 255,
}

impl From<u8> for SliceError {
    fn from(i: u8) -> Self {
        use num_traits::FromPrimitive;
        Self::from_u8(i).unwrap_or(Self::Unknown)
    }
}

extern "C" {
    fn print_log(level: log::Level, memory: u32, ptr: u32, len: u32);

    fn request_uri() -> (i32, i32, i32);

    fn response_status(status: u16) -> SliceError;
    fn response_body(memory: u32, ptr: u32, len: u32);
}

struct Logger;
static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let message = format!("{}", record.args());
        let bytes = message.as_bytes();
        let ptr = bytes.as_ptr();

        unsafe {
            print_log(record.level(), 0, ptr as _, bytes.len() as _);
        }
    }

    fn flush(&self) {}
}

#[export_name = "slice_start"]
pub fn main() -> SliceError {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Trace));

    unsafe {
        response_status(200);
    }

    let (_, ptr, len) = unsafe { request_uri() };
    let uri = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr as _, len as _) });
    log::debug!("uri: {}", uri);

    let body = String::from("test");
    let bytes = body.as_bytes();
    let ptr = bytes.as_ptr();

    unsafe {
        response_body(0, ptr as _, bytes.len() as _);
    }

    log::info!("hello world");

    SliceError::None
}
