use async_std::{fs, io::BufReader, prelude::*, task};
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use error_chain::{bail, error_chain};
use futures::{channel::mpsc::unbounded, stream::TryStreamExt};
use indexmap::IndexMap;
use num_derive::{FromPrimitive, ToPrimitive};
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    ffi::OsStr,
    fmt,
    hash::Hasher,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};
use tide::{Request, Response};
use wasmer_runtime::{compile as compile_wasm, func, imports, Ctx, Module};
use wasmer_runtime_core::module::{ExportIndex, ModuleInfo};

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("only 32 and 64 bit pointers are supported");

fn default_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

fn default_path() -> PathBuf {
    ".".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct Slicefile {
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
    #[serde(with = "humantime_serde", default = "GcOpts::default_interval")]
    pub interval: Duration,
    #[serde(default = "GcOpts::default_invalids")]
    pub keep_invalids: usize,
}

impl GcOpts {
    const fn default_interval() -> Duration {
        Duration::from_secs(5 * 60)
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

#[derive(Debug, Clone, Copy)]
pub enum MetaFormat {
    Cbor,
    Json,
    MsgPack,
}

impl MetaFormat {
    pub fn names() -> Vec<String> {
        [Self::Cbor, Self::Json, Self::MsgPack]
            .iter()
            .map(|f| f.to_string())
            .collect()
    }

    pub fn new(name: &str) -> Result<Self> {
        Ok(match name {
            "cbor" => Self::Cbor,
            "json" => Self::Json,
            "msgpack" => Self::MsgPack,
            name => bail!(ErrorKind::MetaFormatInvalid(name.to_string())),
        })
    }

    pub fn generate<S: Send + Sync>(self, req: &Request<S>) -> Result<Vec<u8>> {
        use tide::http::version::Version;

        #[derive(Serialize)]
        struct Meta<'m> {
            pub version: (u8, u8),
            pub method: &'m str,
            pub uri: &'m str,
            pub headers: Vec<(&'m [u8], &'m [u8])>,
        }

        let uri = req.uri().to_string();
        let meta = Meta {
            version: match req.version() {
                Version::HTTP_09 => (0, 9),
                Version::HTTP_10 => (1, 0),
                Version::HTTP_11 => (1, 1),
                Version::HTTP_2 => (2, 0),
            },
            method: req.method().as_str(),
            uri: uri.as_str(),
            headers: req
                .headers()
                .iter()
                .map(|(key, value)| (key.as_ref(), value.as_bytes()))
                .collect(),
        };

        Ok(match self {
            Self::Cbor => serde_cbor::to_vec(&meta)?,
            Self::Json => serde_json::to_vec(&meta)?,
            Self::MsgPack => rmp_serde::to_vec(&meta)?,
        })
    }

    pub fn parse(self, bytes: &[u8]) -> Result<Response> {
        #[derive(Deserialize)]
        struct Meta {
            pub status: u16,
            pub headers: Vec<(Vec<u8>, Vec<u8>)>,
        }

        let meta: Meta = match self {
            Self::Cbor => serde_cbor::from_slice(bytes)?,
            Self::Json => serde_json::from_slice(bytes)?,
            Self::MsgPack => rmp_serde::from_slice(bytes)?,
        };

        let mut res = tide::http::Response::builder();
        res.status(meta.status);
        for (key, value) in meta.headers {
            res.header(key.as_slice(), value.as_slice());
        }

        let res = res.body(http_service::Body::empty())?;
        Ok(res.into())
    }
}

impl Default for MetaFormat {
    fn default() -> Self {
        Self::Cbor
    }
}

impl fmt::Display for MetaFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Cbor => "cbor",
                Self::Json => "json",
                Self::MsgPack => "msgpack",
            }
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct WasmAllocation {
    pub offset: u32,
    pub length: u32,
}

impl WasmAllocation {
    pub fn new(offset: u32, length: u32) -> Self {
        Self { offset, length }
    }

    pub fn as_slice_range(self) -> std::ops::Range<usize> {
        self.into()
    }

    pub fn check_against_memory(self, ctx: &mut Ctx) -> Result<()> {
        let max = ctx.memory(0).size().bytes().0;
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

    pub fn write(self, ctx: &mut Ctx, bytes: &[u8]) -> Result<u32> {
        if bytes.len() > self.length as _ {
            bail!(ErrorKind::WasmAllocTooSmall(self.length, bytes.len() as _));
        }

        self.check_against_memory(ctx)?;

        log::trace!("writing {} bytes to {:?}", bytes.len(), self);
        let view = ctx.memory(0).view::<u8>().atomically();
        for (i, atom) in view[self.as_slice_range()].iter().enumerate() {
            atom.store(bytes[i], Ordering::SeqCst);
        }

        Ok(bytes.len() as _)
    }

    pub fn read(self, ctx: &mut Ctx) -> Result<Vec<u8>> {
        self.check_against_memory(ctx)?;

        log::trace!("reading from {:?}", self);
        let mut buf: Vec<u8> = Vec::with_capacity(self.length as _);
        let view = ctx.memory(0).view::<u8>().atomically();
        for atom in view[self.as_slice_range()].iter() {
            buf.push(atom.load(Ordering::SeqCst));
        }

        log::trace!("read {} bytes: {:?}", buf.len(), buf);
        Ok(buf)
    }
}

impl From<WasmAllocation> for std::ops::Range<usize> {
    fn from(alloc: WasmAllocation) -> Self {
        (alloc.offset as _)..((alloc.offset + alloc.length) as _)
    }
}

#[derive(Clone)]
pub struct LoadedSlice {
    source_hash: u64,
    created: SystemTime,
    counter: Arc<AtomicUsize>,
    decay: Arc<AtomicBool>,
    module: Module,
    start: &'static str,
    meta_format: MetaFormat,
}

impl fmt::Debug for LoadedSlice {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("LoadedSlice")
            .field("source_hash", &self.source_hash)
            .field("created", &self.created)
            .field("counter", &self.counter)
            .field("decay", &self.decay)
            .field("module", &"<compiled wasmer module>")
            .field("start", &self.start)
            .field("meta_format", &self.meta_format)
            .finish()
    }
}

impl LoadedSlice {
    pub fn new(source: &[u8], hash: u64) -> Result<Self> {
        let module = compile_wasm(source)?;
        let info = module.info();

        let start = Self::detect_start(&info, "slice_start")?;

        let meta_format = info
            .custom_sections
            .get("slicism-meta-format")
            .and_then(|sections| sections.last())
            .and_then(|name| MetaFormat::new(&String::from_utf8_lossy(name)).ok())
            .unwrap_or_default();

        Ok(Self {
            source_hash: hash,
            module,
            created: SystemTime::now(),
            counter: Arc::new(AtomicUsize::new(0)),
            decay: Arc::new(AtomicBool::new(false)),
            start,
            meta_format,
        })
    }

    fn detect_start<'name>(info: &ModuleInfo, name: &'name str) -> Result<&'name str> {
        log::trace!("looking up func: {}", name);
        info.exports
            .get(name)
            .ok_or_else(|| ErrorKind::WasmStartMissing.into())
            .and_then(|index| {
                if let ExportIndex::Func(_) = index {
                    Ok(name)
                } else {
                    bail!(ErrorKind::WasmStartMissing)
                }
            })
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

    pub fn bite<S: Send + Sync + 'static>(&self, req: Request<S>) -> Result<Response> {
        let req_meta = self.meta_format.generate(&req)?;
        let req_meta_size = req_meta.len() as _;

        let (body_sen, mut body_rec) = unbounded();

        let meta_sen = Arc::new(AtomicCell::default());
        let meta_rec = meta_sen.clone();

        let body_lock = futures::lock::Mutex::new(req);

        let imports = imports! {
            "env" => {
                "print_log" => func!(|ctx: &mut Ctx, level: u8, offset: u32, length: u32| {
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
                        }
                    };

                    let message = WasmAllocation::new(offset, length).read(ctx).unwrap();
                    let message = String::from_utf8_lossy(&message);
                    log::log!(level, "{}", message);
                }),

                "size_meta" => func!(move || -> u32 { req_meta_size }),

                "read_meta" => func!(move |ctx: &mut Ctx, offset: u32, length: u32| -> i32 {
                    WasmAllocation::new(offset, length).write(ctx, &req_meta).map(|len| len as _).unwrap_or(-1)
                }),

                "read_body" => func!(move |ctx: &mut Ctx, offset: u32, length: u32| -> i32 {
                    let alloc = WasmAllocation::new(offset, length);
                    let mut buf = vec![0; alloc.length as _];
                    task::block_on(async {
                        let mut req = body_lock.lock().await;
                        req.read(&mut buf).await
                    }).map_err(Into::into).and_then(|len| {
                        alloc.write(ctx, &buf[0..len])
                    }).map(|len| len as _).unwrap_or(-1)
                }),

                "write_meta" => func!(move |ctx: &mut Ctx, offset: u32, length: u32| -> i32 {
                    WasmAllocation::new(offset, length).read(ctx).and_then(|meta| {
                        let len = meta.len() as _;
                        meta_sen.store(meta);
                        Ok(len)
                    }).unwrap_or(-1)
                }),

                "send_meta" => func!(|| -> i32 {
                    // activate true response streaming!
                    // send the request early and hook up the body stream
                    -1
                }),

                "write_body" => func!(move |ctx: &mut Ctx, offset: u32, length: u32| -> i32 {
                    WasmAllocation::new(offset, length).read(ctx).and_then(|body| {
                        let len = body.len() as _;
                        body_sen.unbounded_send(body)?;
                        Ok(len)
                    }).unwrap_or(-1)
                }),
            },
        };

        self.decay.swap(false, Ordering::AcqRel);
        self.counter.fetch_add(1, Ordering::Relaxed);
        self.module.instantiate(&imports)?.call(self.start, &[])?;

        body_rec.close();

        Ok(self
            .meta_format
            .parse(&meta_rec.take())?
            .body(body_rec.map(|chunk| Ok(chunk)).into_async_read()))
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
        Io(::std::io::Error);
        Log(::log::SetLoggerError);

        Cbor(::serde_cbor::error::Error);
        Json(::serde_json::error::Error);
        MsgPackDecode(::rmp_serde::decode::Error);
        MsgPackEncode(::rmp_serde::encode::Error);
        Toml(::toml::de::Error);

        BodyChannel(::futures::channel::mpsc::TrySendError<Vec<u8>>);
        InvalidResponse(::tide::http::Error);

        WasmCompilation(::wasmer_runtime_core::error::CompileError);
        WasmInstantiation(::wasmer_runtime::error::Error);
        WasmCall(::wasmer_runtime_core::error::CallError);
    }

    errors {
        WasmInvalid {
            description("file is invalid wasm")
        }

        WasmStartMissing {
            description("wasm start missing")
            display("missing wasm start export: needs either of slice_start, wasi_start, main")
        }

        WasmAllocTooSmall(alloc: u32, wanted: u32) {
            description("wasm allocation is too small")
            display("wasm allocation is {} bytes, wanted {} bytes", alloc, wanted)
        }

        WasmMemoryTooSmall(memory: u32, wanted: u32) {
            description("wasm memory is too small")
            display("wasm memory is {} bytes, wanted {} bytes", memory, wanted)
        }

        MetaFormatInvalid(name: String) {
            description("invalid meta format requested")
            display("requested unavailable meta format: {}, possibilities: {}", name, MetaFormat::names().join(", "))
        }
    }
}

async fn slicing(req: Request<Arc<State>>) -> Result<Response> {
    let state = req.state();

    let path = req.uri().path();
    // todo: mappings
    let path = state
        .config
        .root
        .join(path.to_string().trim_start_matches('/'));
    // todo: check that we're still in root (security)
    let file = fs::File::open(&path).await?;
    //^ todo: 404 if file does not exist, 401 for wrong permission, 500 for i/o

    if path.extension() == Some(OsStr::new("wasm")) {
        // wasm!
        state.slices.load(path.clone(), file).await?;
        match state.slices.get_loaded(path) {
            Some(Slice::Loaded(slice)) => {
                let res = slice.bite(req)?;
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

async fn handle(req: Request<Arc<State>>) -> Response {
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
        let server = app.listen(state.config.bind);

        let gc_loop = task::spawn(async move {
            loop {
                task::sleep(state.config.gc.interval).await;
                state.gc().await;
            }
        });

        server.await?;
        gc_loop.await;
        Ok(())
    })
}
