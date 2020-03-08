use async_std::{task,fs};
use serde_derive::Deserialize;
use std::{fmt,net::SocketAddr,path::PathBuf,collections::{HashMap},sync::{Arc,Mutex,atomic::AtomicUsize},time::SystemTime};
use regex::Regex;
use wasmer_runtime::Instance;
use tide::{Request,Response};

const fn default_version() -> usize { 1 }

#[derive(Clone, Debug, Deserialize)]
pub struct Slicefile {
    #[serde(default = "default_version")]
    pub version: usize,
    pub bind: SocketAddr,
    pub static_files: bool,
    pub preload: bool,
    pub map: Vec<Mapping>,
    pub cap: Capabilities,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Mapping {
    #[serde(with = "serde_regex")]
    pub src: Regex,
    pub dst: PathBuf,
    #[serde(default)]
    pub post: HashMap<String, String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

//^ todo: preserve post/headers order
// todo: cow strings (and paths?)

#[derive(Clone, Debug, Deserialize)]
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

pub type Slices = HashMap<PathBuf, LoadedSlice>;

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

error_chain::error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Toml(::toml::de::Error);
    }
}

async fn slicing(req: Request<()>) -> Response {
    Response::new(200).body_string("sliced".into())
}


fn main() -> Result<()> {
    task::block_on(async {
        let slicefile: Slicefile = toml::from_str(&fs::read_to_string("Slicefile.toml").await?)?;
        dbg!(&slicefile);

        let mut app = tide::new();
        app.at("/").all(slicing);
        app.at("*").all(slicing);
        app.listen(&slicefile.bind).await?;
        Ok(())
    })
}
