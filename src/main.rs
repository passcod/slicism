use async_std::{fs, io::BufReader, prelude::*, task};
use dashmap::DashMap;
use indexmap::IndexMap;
use num_derive::{FromPrimitive, ToPrimitive};
use regex::Regex;
use serde_derive::Deserialize;
use std::{
    alloc::Layout,
    collections::{hash_map::DefaultHasher, HashMap},
    convert::TryInto,
    ffi::OsStr,
    fmt,
    hash::Hasher,
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    time::SystemTime,
};
use tide::{Request, Response};
use wasmer_runtime::{func, imports, instantiate as instantiate_wasm, Func, Instance};

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
    pub map: Vec<Mapping>,
    #[serde(default)]
    pub cap: Capabilities,
}

impl Slicefile {
    pub async fn normalise(&mut self) -> Result<()> {
        self.root = fs::canonicalize(&self.root).await?.into();
        Ok(())
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

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Capabilities {
    pub net: Option<CapNet>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CapNet {
    pub enabled: bool,
    #[serde(default)]
    pub only: Vec<PathBuf>,
}

#[derive(Clone)]
pub struct LoadedSlice {
    pub source_hash: u64,
    pub instance: Arc<Mutex<Instance>>,
    pub created: SystemTime,
    pub use_counter: Arc<AtomicUsize>,
}

type PtrLen = (u64, u64);

#[derive(FromPrimitive, ToPrimitive)]
#[repr(u8)]
enum WasmRet {
    Success = 0,
    GenericError = 1,
    NotImplemented = 51,
    UnknownError = 255,
}

impl WasmRet {
    pub fn from_wasm(i: u8) -> Self {
        use num_traits::FromPrimitive;
        Self::from_u8(i).unwrap_or(Self::UnknownError)
    }
}

fn request_uri() -> PtrLen {
    (0, 0)
}

fn response_status(status: u32) -> u8 {
    use num_traits::ToPrimitive;
    WasmRet::NotImplemented.to_u8().unwrap()
}

impl LoadedSlice {
    pub fn new(source: &[u8], hash: u64) -> Result<Self> {
        let imports = imports! {
            "env" => {
                "request_uri" => func!(request_uri),
                "response_status" => func!(response_status),
            },
        };

        let instance = instantiate_wasm(source, &imports)?;
        instance.resolve_func("alloc")?;
        instance.resolve_func("dealloc")?;
        instance.resolve_func("main")?;

        Ok(Self {
            source_hash: hash,
            instance: Arc::new(Mutex::new(instance)),
            created: SystemTime::now(),
            use_counter: Default::default(),
        })
    }

    fn alloc(&self, layout: Layout) -> Result<*mut u8> {
        let i = self.instance.lock().unwrap();
        let inner: Func<(u64, u64), u64> = i.func("alloc")?;
        let ptr = inner.call(layout.size().try_into()?, layout.align().try_into()?)?;
        Ok(ptr as *mut u8)
    }

    fn dealloc(&self, ptr: *mut u8, layout: Layout) -> Result<()> {
        let i = self.instance.lock().unwrap();
        let inner: Func<(u64, u64, u64)> = i.func("dealloc")?;
        inner.call(
            ptr as u64,
            layout.size().try_into()?,
            layout.align().try_into()?,
        )?;
        Ok(())
    }

    fn main(&self) -> Result<WasmRet> {
        let i = self.instance.lock().unwrap();
        let inner: Func<(), u8> = i.func("main")?;
        let ret = inner.call()?;
        Ok(WasmRet::from_wasm(ret))
    }
}

impl fmt::Debug for LoadedSlice {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("LoadedSlice")
            .field("source_hash", &self.source_hash)
            .field("instance", &"<wasmer instance>")
            .field("created", &self.created)
            .field("use_counter", &self.use_counter)
            .finish()
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
    pub async fn load(&self, path: PathBuf, mut file: fs::File) -> Result<()> {
        // todo: debug logging throughout here

        let meta = file.metadata().await?;
        let modtime = meta.modified().or_else(|_| meta.created())?;

        if let Some(r) = self.from_path.get(&path) {
            let hash = r.value();
            if let Some(r) = self.from_hash.get(&hash) {
                match r.value() {
                    Slice::InvalidWasm { seen } if modtime <= *seen => {
                        return Err(ErrorKind::InvalidWasm.into())
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
                    return Err(ErrorKind::InvalidWasm.into());
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
                Err(ErrorKind::InvalidWasm.into())
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
        WasmInstantiation(::wasmer_runtime::error::Error);
        WasmExportMissing(::wasmer_runtime_core::error::ResolveError);
        WasmCall(::wasmer_runtime_core::error::RuntimeError);
    }

    errors {
        InvalidWasm {
            description("file is invalid wasm")
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
        state.slices.load(path, file).await?;
        Ok(Response::new(200).body_string("wasm loaded".into()))
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
