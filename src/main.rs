use async_std::{fs, io::BufReader, prelude::*, task};
use dashmap::DashMap;
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
use wasmer_runtime_core::module::ExportIndex;

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

pub struct WasmAllocation {
    pub memory: u32,
    pub offset: usize,
    pub length: usize,
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
            (*mv as u32, *ov as u32 as _, *sv as u32 as _)
        }
        _ => return Err(ErrorKind::WasmTypeMismatch("u32").into()),
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
fn wasm_dealloc(ctx: &mut Ctx, index: TableIndex, memory: u32, layout: Layout) -> Result<()> {
    let memory = WasmValue::I32(memory as _);
    let size = WasmValue::I32(layout.size() as _);
    let align = WasmValue::I32(layout.align() as _);

    ctx.call_with_table_index(index, &[memory, size, align])?;
    Ok(())
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
        let alloc_index = Self::func_index(&module, "alloc")?;
        let dealloc_index = Self::func_index(&module, "dealloc")?;

        Ok(Self {
            source_hash: hash,
            module,
            created: SystemTime::now(),
            counter: Arc::new(AtomicUsize::new(0)),
            decay: Arc::new(AtomicBool::new(false)),
            alloc_index,
            dealloc_index,
        })
    }

    fn func_index(module: &Module, name: &'static str) -> Result<TableIndex> {
        let export_index = module
            .info()
            .exports
            .get(name)
            .ok_or_else(|| ErrorKind::WasmExportMissing(name))?;
        if let ExportIndex::Func(func_index) = export_index {
            Ok(unsafe { std::mem::transmute(*func_index) })
        } else {
            Err(ErrorKind::WasmExportMissing(name).into())
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
                "request_uri" => {
                    let req = req.clone();
                    func!(move |ctx: &mut Ctx| -> PtrLen {
                        let uri = &req.uri;
                        (0, 0)
                    })
                },
                "response_status" => {
                    let res = res.clone();
                    func!(move |status: u16| -> u8 {
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
            },
        };

        self.counter.fetch_add(1, Ordering::Relaxed);

        // Instantiate and immediately drop. Why? Because instantiate runs the module's start
        // function (equiv to main()). That runs everything the module should do, and has access to
        // the imports above, plus we do ctx-wrangling to get to the alloc and dealloc exports.
        // Thus, once the instantiate call is done, the module has fulfilled its purpose, and we
        // trash it.
        //
        // This is what ensures isolation: each call to a module is a brand new instance, with no
        // shared state. We only compile once, though.
        //
        // The reason this is in braces here rather than relying on implicit drop at the end of fn
        // scope is to guarantee the instance has dropped before we unwrap the Arc<Mutex> of the
        // Response and load the exit code.
        {
            self.module.instantiate(&imports)?;
        }

        match WasmError::from_wasm(exit.load(Ordering::SeqCst)) {
            WasmError::None => Ok(res.lock().unwrap().clone().into()),
            error => Err(ErrorKind::WasmError(error).into()),
        }
    }
}

#[derive(Clone, Debug)]
struct FlatRequest {
    pub uri: String,
}

impl<S> From<&Request<S>> for FlatRequest {
    fn from(req: &Request<S>) -> Self {
        Self {
            uri: req.uri().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct FlatResponse {
    pub status: u16,
}

impl FlatResponse {
    fn new() -> Self {
        Self { status: 501 }
    }
}

impl From<FlatResponse> for Response {
    fn from(res: FlatResponse) -> Self {
        Self::new(res.status)
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
                        return Err(ErrorKind::WasmInvalid.into())
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
                    return Err(ErrorKind::WasmInvalid.into());
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
                Err(ErrorKind::WasmInvalid.into())
            }
        }
    }
}

error_chain::error_chain! {
    foreign_links {
        IntConversion(::std::num::TryFromIntError);
        Io(::std::io::Error);
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

        WasmError(e: WasmError) {
            description("wasm internal error")
            display("wasm internal error: {:?} ({})", e, e.code())
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
