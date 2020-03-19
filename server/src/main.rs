use async_std::{fs, io::BufReader, prelude::*, task};
use dashmap::DashMap;
use error_chain::{bail, error_chain};
use indexmap::IndexMap;
use num_derive::{FromPrimitive, ToPrimitive};
use regex::Regex;
use serde_derive::Deserialize;
use std::{
    alloc::Layout,
    collections::{hash_map::DefaultHasher, BTreeMap},
    convert::TryInto,
    ffi::OsStr,
    fmt,
    hash::Hasher,
    mem::align_of,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::SystemTime,
};
use tide::{Request, Response};
use wasmer_runtime::{
    compile as compile_wasm, func, imports,
    types::{TableIndex, Value as WasmValue},
    Ctx, Module,
};
use wasmer_runtime_core::module::{ExportIndex, ModuleInfo};

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("only 32 and 64 bit pointers are supported");

const fn default_version() -> usize {
    1
}

fn default_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

fn default_path() -> PathBuf {
    ".".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct Slicefile {
    #[serde(default = "default_version")]
    pub version: usize,
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_path")]
    pub root: PathBuf,
    #[serde(default)]
    pub display_errors: bool,
    #[serde(default)]
    pub static_files: bool,
    #[serde(default)]
    pub preload: bool,
    #[serde(default)]
    pub gc: GcOpts,
    #[serde(default)]
    pub map: Vec<Mapping>,
}

impl Slicefile {
    pub async fn normalise(&mut self) -> Result<()> {
        self.root = fs::canonicalize(&self.root).await?.into();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GcOpts {
    #[serde(default = "GcOpts::default_interval")]
    pub interval: usize,
    #[serde(default = "GcOpts::default_invalids")]
    pub keep_invalids: usize,
}

impl GcOpts {
    const fn default_interval() -> usize {
        300
    }
    const fn default_invalids() -> usize {
        100
    }
}

impl Default for GcOpts {
    fn default() -> Self {
        Self {
            interval: Self::default_interval(),
            keep_invalids: Self::default_invalids(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Mapping {
    #[serde(with = "serde_regex")]
    pub src: Regex,
    pub dst: PathBuf,
    #[serde(default)]
    pub post: IndexMap<String, String>,
    #[serde(default)]
    pub headers: IndexMap<String, String>,
}

type PtrLen = (u32, u32);

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum WasmError {
    None = 0,
    Generic = 1,
    Alloc = 2,
    NotImplemented = 51,

    InvalidResponse = 100,
    StatusOutOfBounds = 101,

    Unknown = 255,
}

impl WasmError {
    pub fn from_wasm(i: u8) -> Self {
        use num_traits::FromPrimitive;
        Self::from_u8(i).unwrap_or(Self::Unknown)
    }

    pub fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct WasmAllocation {
    pub memory: u32,
    pub offset: u32,
    pub length: u32,
}

impl WasmAllocation {
    pub fn as_wasm_ptr(&self) -> (u32, u32, u32) {
        (self.memory, self.offset, self.length)
    }

    pub fn from_wasm(memory: u32, offset: u32, length: u32) -> Self {
        Self {
            memory,
            offset,
            length,
        }
    }

    pub fn to_wasm(&self) -> [WasmValue; 3] {
        [
            WasmValue::I32(self.memory as _),
            WasmValue::I32(self.offset as _),
            WasmValue::I32(self.length as _),
        ]
    }

    pub fn as_slice_range(&self) -> std::ops::Range<usize> {
        (self.offset as _)..((self.offset + self.length) as _)
    }

    pub fn check_against_memory(&self, ctx: &mut Ctx) -> Result<()> {
        let max = ctx.memory(self.memory).size().bytes().0;
        let max = if max > std::u32::MAX as usize {
            panic!("memory size of wasm is somehow > u32::MAX");
        } else {
            max as u32
        };

        if self.offset > max {
            bail!(ErrorKind::WasmMemoryTooSmall(
                max,
                self.offset + self.length
            ));
        }

        Ok(())
    }
}

/// Allocate memory inside wasm
///
/// # Errors
///
///  - [`WasmError`](ErrorKind::WasmError)` containing [`WasmError::Alloc`], specifies that the
///    allocation itself inside wasm failed. This may be recoverable (e.g. by growing the
///    instance memory).
///
///  - [`WasmCall`](ErrorKind::WasmCall) is the call to the wasm instance failing. This is not
///    recoverable and the instance should be considered crashed.
///
///  - [`WasmTypeMismatch`](ErrorKind::WasmTypeMismatch) means the wasm allocator returned the
///    wrong type. This is not recoverable and the _module_ should be considered invalid.
///
fn wasm_alloc(ctx: &mut Ctx, index: TableIndex, layout: Layout) -> Result<WasmAllocation> {
    let size: u32 = layout.size().try_into()?;
    let align: u32 = layout.align().try_into()?;

    let res = ctx.call_with_table_index(
        index,
        &[WasmValue::I32(size as _), WasmValue::I32(align as _)],
    )?;

    let (memory, offset, length) = match res.as_slice() {
        [WasmValue::I32(mv), WasmValue::I32(ov), WasmValue::I32(sv)] => {
            (*mv as u32, *ov as u32, *sv as u32)
        }
        _ => bail!(ErrorKind::WasmTypeMismatch("u32")),
    };

    Ok(WasmAllocation {
        memory,
        offset,
        length,
    })
}

/// De-allocate memory inside wasm
///
/// # Errors
///
///  - [`WasmCall`](ErrorKind::WasmCall) is the call to the wasm instance failing. This is not
///    recoverable and the instance should be considered crashed.
///
#[allow(dead_code)] // not used, but keeping just in case
fn wasm_dealloc(ctx: &mut Ctx, index: TableIndex, alloc: &WasmAllocation) -> Result<()> {
    ctx.call_with_table_index(index, &alloc.to_wasm())?;
    Ok(())
}

fn wasm_write(ctx: &mut Ctx, alloc: &WasmAllocation, bytes: &[u8]) -> Result<()> {
    if bytes.len() > alloc.length as _ {
        bail!(ErrorKind::WasmAllocTooSmall(alloc.length, bytes.len() as _));
    }

    alloc.check_against_memory(ctx)?;

    let view = ctx.memory(alloc.memory).view::<u8>().atomically();
    for (i, atom) in view[alloc.as_slice_range()].iter().enumerate() {
        atom.store(bytes[i], Ordering::SeqCst);
    }

    Ok(())
}

fn wasm_alloc_and_write(
    ctx: &mut Ctx,
    alloc_index: TableIndex,
    bytes: impl AsRef<[u8]>,
) -> Result<WasmAllocation> {
    let bytes = bytes.as_ref();
    let layout = Layout::from_size_align(bytes.len(), align_of::<u8>())?;
    let alloc = wasm_alloc(ctx, alloc_index, layout)?;
    wasm_write(ctx, &alloc, bytes)?;
    Ok(alloc)
}

fn wasm_read(ctx: &mut Ctx, alloc: &WasmAllocation) -> Result<Vec<u8>> {
    alloc.check_against_memory(ctx)?;

    let mut buf: Vec<u8> = Vec::with_capacity(alloc.length as _);
    let view = ctx.memory(alloc.memory).view::<u8>().atomically();
    for atom in view[alloc.as_slice_range()].iter() {
        buf.push(atom.load(Ordering::SeqCst));
    }

    Ok(buf)
}

#[derive(Clone)]
pub struct LoadedSlice {
    source_hash: u64,
    created: SystemTime,
    counter: Arc<AtomicUsize>,
    decay: Arc<AtomicBool>,
    module: Module,
    alloc_index: TableIndex,
    dealloc_index: TableIndex,
    start: &'static str,
}

impl fmt::Debug for LoadedSlice {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("LoadedSlice")
            .field("source_hash", &self.source_hash)
            .field("created", &self.created)
            .field("counter", &self.counter)
            .field("decay", &self.decay)
            .field("module", &"<compiled wasmer module>")
            .field("alloc_index", &unsafe {
                std::mem::transmute::<_, u32>(self.alloc_index)
            })
            .field("dealloc_index", &unsafe {
                std::mem::transmute::<_, u32>(self.dealloc_index)
            })
            .finish()
    }
}

impl LoadedSlice {
    pub fn new(source: &[u8], hash: u64) -> Result<Self> {
        let module = compile_wasm(source)?;
        let info = module.info();

        let alloc_index = Self::func_index(&info, "alloc")?;
        let dealloc_index = Self::func_index(&info, "dealloc")?;

        let start = {
            const START_NAMES: [&'static str; 3] = ["slice_start", "wasi_start", "main"];

            Self::func_index(&info, START_NAMES[0])
                .map(|_| START_NAMES[0])
                .or_else(|_| Self::func_index(&info, START_NAMES[1]).map(|_| START_NAMES[1]))
                .or_else(|_| Self::func_index(&info, START_NAMES[2]).map(|_| START_NAMES[2]))
                .map_err(|_| ErrorKind::WasmStartMissing)?
        };

        Ok(Self {
            source_hash: hash,
            module,
            created: SystemTime::now(),
            counter: Arc::new(AtomicUsize::new(0)),
            decay: Arc::new(AtomicBool::new(false)),
            alloc_index,
            dealloc_index,
            start,
        })
    }

    fn func_index(info: &ModuleInfo, name: &'static str) -> Result<TableIndex> {
        let export_index = info
            .exports
            .get(name)
            .ok_or_else(|| ErrorKind::WasmExportMissing(name))?;
        if let ExportIndex::Func(func_index) = export_index {
            Ok(unsafe { std::mem::transmute(*func_index) })
        } else {
            bail!(ErrorKind::WasmExportMissing(name))
        }
    }

    pub fn source_hash(&self) -> u64 {
        self.source_hash
    }

    pub fn created(&self) -> &SystemTime {
        &self.created
    }

    pub fn counter(&self) -> usize {
        self.counter.load(Ordering::Relaxed)
    }

    pub fn bite<S: Send + Sync>(&self, req: &Request<S>) -> Result<Response> {
        let req = Arc::new(FlatRequest::from(req));
        let res = Arc::new(Mutex::new(FlatResponse::new()));
        let exit = Arc::new(AtomicU8::new(0));

        let imports = imports! {
            "env" => {
                "print_log" => func!(|ctx: &mut Ctx, level: u8, mem: u32, ptr: u32, len: u32| {
                    use log::Level::*;
                    const LOG_ERROR: u8 = Error as u8;
                    const LOG_WARN: u8 = Warn as u8;
                    const LOG_INFO: u8 = Info as u8;
                    const LOG_DEBUG: u8 = Debug as u8;
                    const LOG_TRACE: u8 = Trace as u8;
                    let level = match level {
                        LOG_ERROR => Error,
                        LOG_WARN => Warn,
                        LOG_INFO => Info,
                        LOG_DEBUG => Debug,
                        LOG_TRACE => Trace,
                        unk => {
                            log::warn!("unknown error level used in wasm: {}", unk);
                            Info
                        },
                    };

                    let alloc = WasmAllocation::from_wasm(mem, ptr, len);
                    let message = wasm_read(ctx, &alloc).unwrap();
                    let message = String::from_utf8_lossy(&message);
                    log::log!(level, "{}", message);
                }),
                "exit_get" => {
                    let exit = exit.clone();
                    func!(move || -> u8 {
                        exit.load(Ordering::Acquire)
                    })
                },
                "exit_set" => {
                    let exit = exit.clone();
                    func!(move |s: u8| {
                        exit.store(s, Ordering::Release)
                    })
                },
                "request_method" => {
                    let req = req.clone();
                    let alloc_index = self.alloc_index;
                    func!(move |ctx: &mut Ctx| -> (u32, u32, u32) {
                        wasm_alloc_and_write(ctx, alloc_index, &req.method).unwrap().as_wasm_ptr()
                    })
                },
                "request_uri" => {
                    let req = req.clone();
                    let alloc_index = self.alloc_index;
                    func!(move |ctx: &mut Ctx, what: u32| {
                        dbg!(what);
                        // wasm_alloc_and_write(ctx, alloc_index, &req.uri).unwrap().as_wasm_ptr()
                    })
                },
                "response_status" => {
                    let res = res.clone();
                    func!(move |status: u16| -> u8 {
                        log::debug!("response_status called");
                        match tide::http::StatusCode::from_u16(status) {
                            Ok(_) => {
                                let mut res = res.lock().unwrap();
                                res.status = status;
                                WasmError::None
                            }
                            Err(_) => {
                                WasmError::StatusOutOfBounds
                            }
                        }.code()
                    })
                },
                "response_body" => {
                    let res = res.clone();
                    func!(move |ctx: &mut Ctx, mem: u32, ptr: u32, len: u32| {
                        log::debug!("response_body called");
                        let alloc = WasmAllocation::from_wasm(mem, ptr, len);
                        log::debug!("got alloc: {:?}", alloc);
                        let body = wasm_read(ctx, &alloc).unwrap();
                        log::debug!("got body: {:?}", body);
                        let mut res = res.lock().unwrap();
                        res.body = body;
                        log::debug!("wrote body");
                    })
                },
            },
        };

        self.counter.fetch_add(1, Ordering::Relaxed);

        // Instantiate, call start, and immediately drop.
        //
        // This is what ensures isolation: each call to a module is a brand new instance, with no
        // shared state beyond safe loads and stores via us. We only compile bytecode once, though.
        {
            match self
                .module
                .instantiate(&imports)?
                .call(self.start, &[])?
                .as_slice()
            {
                [WasmValue::I32(code)] => {
                    exit.store(*code as _, Ordering::SeqCst);
                }
                _ => {}
            }
        }

        match WasmError::from_wasm(exit.load(Ordering::SeqCst)) {
            WasmError::None => Ok(res.lock().unwrap().clone().into()),
            error => bail!(ErrorKind::WasmError(error)),
        }
    }
}

#[derive(Clone, Debug)]
struct FlatRequest {
    pub method: String,
    pub uri: String,
}

impl<S> From<&Request<S>> for FlatRequest {
    fn from(req: &Request<S>) -> Self {
        Self {
            method: req.method().to_string(),
            uri: req.uri().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct FlatResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl FlatResponse {
    fn new() -> Self {
        Self {
            status: 501,
            body: Vec::new(),
        }
    }
}

impl From<FlatResponse> for Response {
    fn from(res: FlatResponse) -> Self {
        let cursor = futures::io::Cursor::new(res.body);
        Self::new(res.status).body(cursor)
    }
}

#[derive(Clone, Debug)]
pub enum Slice {
    InvalidWasm { seen: SystemTime },
    Loaded(LoadedSlice),
}

#[derive(Clone, Debug, Default)]
pub struct Slices {
    from_path: DashMap<PathBuf, u64>,
    from_hash: DashMap<u64, Slice>,
}

impl Slices {
    pub fn get_loaded(&self, path: PathBuf) -> Option<Slice> {
        self.from_path
            .get(&path)
            .and_then(|hash| self.from_hash.get(hash.value()))
            .map(|slice| slice.value().clone())
    }

    pub async fn load(&self, path: PathBuf, mut file: fs::File) -> Result<()> {
        // todo: debug logging throughout here

        let meta = file.metadata().await?;
        let modtime = meta.modified().or_else(|_| meta.created())?;

        if let Some(r) = self.from_path.get(&path) {
            let hash = r.value();
            if let Some(r) = self.from_hash.get(&hash) {
                match r.value() {
                    Slice::InvalidWasm { seen } if modtime <= *seen => {
                        bail!(ErrorKind::WasmInvalid)
                    }
                    Slice::Loaded(LoadedSlice { created, .. }) if modtime < *created => {
                        return Ok(())
                    } // already loaded
                    _ => {
                        // needs a re-hash
                    }
                }
            } else {
                // the from_path entry is stale
                self.from_path.remove(&path);
            }
        } // else: new entry

        let mut full = Vec::new();
        file.read_to_end(&mut full).await?;

        // todo: stream the file to hash first before committing to load
        // it entirely in memory once we absolutely know that's needed.
        let mut hasher = DefaultHasher::new();
        hasher.write(&full);
        let hash = hasher.finish();

        if let Some(r) = self.from_hash.get(&hash) {
            match r.value() {
                Slice::InvalidWasm { .. } => {
                    // we already know it's bad, so bail
                    self.from_path.insert(path, hash);
                    bail!(ErrorKind::WasmInvalid);
                }
                Slice::Loaded(_) => {
                    // we already know it's good, so bail
                    self.from_path.insert(path, hash);
                    return Ok(());
                }
            }
        } // else: new entry

        match LoadedSlice::new(&full, hash) {
            Ok(slice) => {
                self.from_hash.insert(hash, Slice::Loaded(slice));
                self.from_path.insert(path, hash);
                Ok(())
            }
            Err(err) => {
                log::error!(
                    "error loading wasm file={} hash={}: {}",
                    path.display(),
                    hash,
                    err
                );
                self.from_hash.insert(
                    hash,
                    Slice::InvalidWasm {
                        seen: SystemTime::now(),
                    },
                );
                self.from_path.insert(path, hash);
                bail!(ErrorKind::WasmInvalid)
            }
        }
    }
}

error_chain! {
    foreign_links {
        IntConversion(::std::num::TryFromIntError);
        Io(::std::io::Error);
        Layout(::std::alloc::LayoutErr);
        Log(::log::SetLoggerError);
        Toml(::toml::de::Error);
        WasmCompilation(::wasmer_runtime_core::error::CompileError);
        WasmInstantiation(::wasmer_runtime::error::Error);
        WasmCall(::wasmer_runtime_core::error::CallError);
    }

    errors {
        WasmInvalid {
            description("file is invalid wasm")
        }

        WasmNullPtr {
            description("wasm returned a null pointer")
        }

        WasmTypeMismatch(expected: &'static str) {
            description("unexpected type returned from wasm")
            display("unexpected type returned from wasm, expected {}", expected)
        }

        WasmExportMissing(e: &'static str) {
            description("wasm export missing")
            display("missing wasm export: {}", e)
        }

        WasmStartMissing {
            description("wasm start missing")
            display("missing wasm start export: needs either of slice_start, wasi_start, main")
        }

        WasmError(e: WasmError) {
            description("wasm internal error")
            display("wasm internal error: {:?} ({})", e, e.code())
        }

        WasmAllocTooSmall(alloc: u32, wanted: u32) {
            description("wasm allocation is too small")
            display("wasm allocation is {} bytes, wanted {} bytes", alloc, wanted)
        }

        WasmMemoryTooSmall(memory: u32, wanted: u32) {
            description("wasm memory is too small")
            display("wasm memory is {} bytes, wanted {} bytes", memory, wanted)
        }
    }
}

async fn slicing(req: Request<S>) -> Result<Response> {
    let state = req.state();

    let path = req.uri();
    // todo: mappings
    let path = state
        .config
        .root
        .join(path.to_string().trim_start_matches('/'));
    let file = fs::File::open(&path).await?;
    //^ todo: 404 if file does not exist, 401 for wrong permission, 500 for i/o

    if path.extension() == Some(OsStr::new("wasm")) {
        // wasm!
        state.slices.load(path.clone(), file).await?;
        match state.slices.get_loaded(path) {
            Some(Slice::Loaded(slice)) => {
                let res = slice.bite(&req)?;
                dbg!(&slice.counter);
                Ok(res)
            }
            Some(Slice::InvalidWasm { .. }) => Ok(Response::new(500)),
            None => Ok(Response::new(404)),
        }
    } else if state.config.static_files {
        Ok(Response::with_reader(200, BufReader::new(file)))
    } else {
        Ok(Response::new(404))
    }
}

pub type S = Arc<State>;
pub struct State {
    pub config: Slicefile,
    pub slices: Slices,
}

impl State {
    fn new(config: Slicefile) -> Arc<Self> {
        Arc::new(Self {
            config,
            slices: Slices::default(),
        })
    }

    // run every <config.gc.interval> default 1h
    async fn gc(&self) {
        let mut unload_list = Vec::new();
        let mut invalids = BTreeMap::new();
        for r in self.slices.from_hash.iter() {
            match r.value() {
                Slice::Loaded(slice) => {
                    let decayed = slice.decay.swap(true, Ordering::AcqRel);
                    if decayed {
                        unload_list.push(*r.key());
                    }
                }
                Slice::InvalidWasm { seen } => {
                    invalids.insert(seen.clone(), *r.key());
                }
            }
        }

        if invalids.len() > self.config.gc.keep_invalids {
            for (_, hash) in invalids.into_iter().skip(self.config.gc.keep_invalids) {
                unload_list.push(hash);
            }
        }

        for hash in unload_list.into_iter() {
            // todo: take out of from_path
            self.slices.from_hash.remove(&hash);
        }
    }
}

async fn handle(req: Request<S>) -> Response {
    let display_errors = req.state().config.display_errors;
    let uri = req.uri().clone();

    slicing(req).await.unwrap_or_else(|err| {
        if display_errors {
            Response::new(500).body_string(format!("Slicism error: {}", err))
        } else {
            log::error!("While processing {}, got error: {}", uri, err);
            Response::new(500)
        }
    })
}

fn main() -> Result<()> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}\t[{}] {}",
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .level_for("slicism_server", log::LevelFilter::Trace)
        .chain(std::io::stderr())
        .apply()?;

    task::block_on(async {
        let mut slicefile: Slicefile =
            toml::from_str(&fs::read_to_string("Slicefile.toml").await?)?;
        slicefile.normalise().await?;
        dbg!(&slicefile);
        let state = State::new(slicefile);

        let mut app = tide::with_state(state.clone());
        app.at("/").all(handle);
        app.at("*").all(handle);
        app.listen(&state.config.bind).await?;
        Ok(())
    })
}
