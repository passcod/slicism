use clap::arg_enum;
use error_chain::error_chain;
use std::path::PathBuf;
use structopt::StructOpt;
use walrus::{Module, RawCustomSection};

error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Walrus(::anyhow::Error);
    }

    errors {
    }
}

arg_enum! {
    #[allow(non_camel_case_types)]
    #[derive(Debug)]
    enum MetaFormat {
        cbor,
        json,
        msgpack,
    }
}

/// Prints and edits slicism custom section attributes
///
/// Always prints the current settings as read (prints nothing if no settings
/// present), then applies the provided settings (if any).
#[derive(StructOpt, Debug)]
struct Opt {
    /// Sets the slicism-meta-format section
    #[structopt(long, possible_values = &MetaFormat::variants())]
    meta_format: Option<MetaFormat>,

    #[structopt()]
    wasm_file: PathBuf,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let mut changed = false;
    let mut module = Module::from_file(&opt.wasm_file)?;

    const PREFIX: &'static str = "slicism-";

    for (_, section) in module.customs.iter() {
        if let Some(section) = section.as_any().downcast_ref::<RawCustomSection>() {
            if section.name.starts_with(PREFIX) {
                let key = section.name.replace(PREFIX, "");
                let value = String::from_utf8(section.data.clone())
                    .unwrap_or_else(|_| hex::encode(&section.data));
                println!("{}: {}", key, value);
            }
        }
    }

    if let Some(meta_format) = opt.meta_format {
        let section = RawCustomSection {
            name: format!("{}meta-format", PREFIX),
            data: format!("{}", meta_format).as_bytes().to_vec(),
        };

        module.customs.add(section);
        changed = true;
    }

    if changed {
        module.emit_wasm_file(opt.wasm_file)?;
    }

    Ok(())
}
