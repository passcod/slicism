# Slicism

_A bad idea._

[![License: Artistic-2.0](https://flat.badgen.net/github/license/passcod/slicism)](./LICENSE)
![MSRV: latest stable](https://flat.badgen.net/badge/MSRV/latest%20stable/blue)
![MSRV policy: none](https://flat.badgen.net/badge/MSRV%20policy/none/red)

Slicism (slice-ism) is an HTTP server that passes requests to Wasm programs, a
lot like PHP does, but for Web Assembly.

Each request is processed in a single invocation of the corresponding wasm
program, providing similar isolation guarantees to, yes, PHP.

The difference with PHP is you can use anything that compiles to Web Assembly,
it's probably pretty fast, and you don't get any of the large standard library
that PHP provides. Oh, and also at the moment you can't interact with the
world: no reading files, no accessing the network, no persistent state, no
databases, no battle-tested production web engine, nothing.

Yet.

Some things may or may not be coming:

## Todo

In rough order.

- [ ] Mappings (URL rewriting)
- [ ] Preloading (walking the root and loading every wasm found at start time)
- [ ] Static files (for dev ease, production should use nginx)
- [ ] Access to the world for Wasm (at least reading the filesystem)
- [ ] Error value mapping
- [ ] Logging control in config
- [ ] Logging cleanup
- [ ] Stats (in statsd/influx format, to some UDP/TCP/file as configured)

## So what's the point then?

This was really just a bit of fun and a good strong intro to writing a Wasm
integration from both the engine side and the wasm side. I learned a lot.

The idea is pretty sound, though, as much as I like to call it "a bad idea."

Also once I get filesystem reading working (without WASI, because that is _not_
ready), I plan on migrating my blog to it and putting it in production.
Non-critical production, but like, exposed to the internet and everything.

## Sounds... fun, good luck with that

Thanks!

## I'm really bored / somehow interested / not entirely quite right / want to use this

Okay! You can do this.

The first thing you need to know is that despite the version number being at
(or over) 1.0.0, this is in no way stable. I will endeavour to keep to semver!
That just might mean that things breaking were actually bugs, and the version
will shoot up quickly. I am of the school of thought that the 0.x.y range is a
mistake and using all three numbers is useful regardless of how stable your
project is.

There are three parts to using Slicism: installing, configuring, and writing
programs.

### Installing

There's currently only one way to do this:

```
cargo install --git https://github.com/passcod/slicism
```

It will take a while because release build. It might be tempting to use
`--debug` to get started faster! The issue with this is that cold starts for
wasm programs with the debug builds are _really slow_: they can get into the
_tens of seconds_. That's awful, so go wash your hands for like, five minutes.

You will get two executables:

- `slicism-server` is the HTTP server.
- `slicism-edit` is a utility to read and write slicism wasm-embedded settings.

We'll talk about both of them.

### Configuring

To start with slicism you'll need a `Slicefile.toml`.

You can put that file anywhere, but at the moment `slicism-server` expects it's
in the working directory, so you'll at least need to `cd` there to start it off.

Every top-level field and section in the file is optional, but you still need
the file at the moment.

```toml
# The address to bind the server to. This can be anything that parses or
# resolves to an IP address and port, including domain names. The default is
# 127.0.0.1:8080. You'll need sufficient privileges to bind and listen there.
#
bind = "0.0.0.0:7269"

# The document root of the server. When looking up files, the server will start
# from there and won't look higher. Wasm files will get executed, other files
# will get output verbatim. The default is the current working directory.
#
root = "./slices"

# Whether errors should get returned with the HTTP response or output on the
# server logs. In production, this should be false (the default). In
# development, it can be useful to turn on.
#
display_errors = true

# Whether static files should be handled (returned verbatim). In production,
# Slicism should be behind a reverse proxy that handles files properly, with
# all the support for streaming, resuming, caching, etc. In development, it's
# often useful to have slicism do that for you. The default is off.
# (not yet implemented)
#
static_files = true

# Whether the document root should be walked at start time and all wasm programs
# found within loaded pre-emptively. This is recommended in production, as it
# effectively removes cold starts. However, it increases start up time and also
# increases memory use. Also consider the gc options when configuring this.
# Default is off.
# (not yet implemented)
#
preload = true

# Configuration for garbage collection (gc) of loaded wasm programs. This is a
# simple mark-and-sweep collector: at every interval, all marked programs are
# unloaded, and all remaining programs are marked; on use, programs unmark
# themselves. Unloaded programs are loaded from file and compiled on next use.
#
[gc]

# The interval the gc runs at. Syntax is everything the humantime crate supports,
# e.g. "5min 30s", "1h", "2week". Defaults to 5 minutes.
#
interval = "2months"

# The collector also sweeps invalid program tombstones. These are markers that
# indicate a program at a path and with a certain content (checksummed) has
# already been attempted to be loaded and was found invalid, so Slicism skips
# it early rather than retrying. These tombstones can pile up in memory,
# especially in development, if there are many changes. This value controls how
# many such tombstones should be kept. Defaults to 100.
#
keep_invalids = 5000
```

### Writing programs

Programs are written in (whatever you want) and compiled to Web Assembly.

Slicism specifically supports Wasm32. Wasm64 is not supported. WASI is not
supported. There is no particular calling convention, the function signatures
described are what Slicism supports directly, and are expressed in Wasm text
format.

There is a support library crate `slicism-rust-support` to make the Rust
experience ergonomic, but it is not required.

#### Types

There are two important types to know about when using the interface:
allocations and io results.

Allocations are `i64` values at the wasm level, but should be interpreted as
`(u32, u32)`: two u32 values laid out next to each other. To read, cast the
`i64` as `u64`, read all eight bytes in little-endian order, then write the
first four bytes in little-endian to `u32`, and similarly for the last four.

To write, perform the reverse operation.

Allocations encode an offset (pointer) and length inside the wasm memory, and
are used to ask the host for data to be read from or written to wasm memory.

I/O Results are `i32` values. Positive (including zero) values indicate the
amount of bytes read or written. Negative values indicate an error. There is no
mapping from error values to error kinds yet.

#### Imports

The import namespace is `env` (the de-facto default for wasm modules).

##### `(func (import "env" "print_log") (param i32 i64))`

Interpreted as: `fn print_log(level: u8, alloc: u64)`.

Prints a log message to the server log. The level corresponds to the Rust
log::Level enum values. Currently:

- Trace: 1
- Debug: 2
- Info: 3 (default if another value is given)
- Warn: 4
- Error: 5

The message is read as a UTF-8 string (lossy conversion) from the allocation
given. Errors are silently ignored.

##### `(func (import "env" "size_meta") (result i32))`

Interpreted as `fn size_meta() -> u32`.

This should really be a read-only Global, but Wasm language implementors are
stubborn in only supporting functions as imports and exports.

This is the size of the request metadata blob. When allocating space to read
that, you'll need to allocate at least that. Partial metadata reads aren't
supported, so that's non-negotiable unless you don't want to read request meta.

##### `(func (import "env" "read_meta") (param i64) (result i32))`

Interpreted as `fn read_meta(alloc: u64) -> i32`.

Writes the request meta blob into an allocation. Returns an I/O result.

You should then parse the meta blob. The blob is encoded with a self-describing
format, by default CBOR. You can select which format is used by writing in a
custom section on the wasm binary file, with the name `slicism-meta-format` and
one of the following byte strings:

- `cbor` for CBOR (default)
- `json` for JSON
- `msgpack` for MessagePack

If an invalid byte string is found, the wasm program will have been marked
invalid on load and an error returned. If multiple custom sections named
`slicism-meta-format` exist, the last one is used.

You can use the `slicism-edit` tool to get or set this custom section:

```bash
$ slicism-edit slice.wasm
# (nothing returned == no settings currently set)

$ slicism-edit --meta-format=json slice.wasm
# (returns the previous settings)

$ slicism-edit slice.wasm
meta-format: json
```

The request meta blob decodes to this structure:

```rust
struct {
    version: (u8, u8),
    method: String,
    uri: String,
    headers: Vec<(ByteString, ByteString)>,
}
```

The version is `(1, 1)` for HTTP/1.1 and `(2, 0)` for HTTP/2 (etc).

The method and URI are UTF-8 strings.

The headers are an array (vec) of bytestring-bytestring key-value pairs. HTTP
headers are somewhat more restrained than UTF-8 or ASCII: only byte values
between 32 and 255 (inclusive) are permitted, excluding byte 127 (DEL).
Header names must in addition be all-lowercase.

##### `(func (import "env" "write_meta") (param i64) (result i32))`

Interpreted as `fn write_meta(alloc: u64) -> i32`.

Reads a response meta blob from an allocation. Returns an I/O result.

The same encoding format as in `read_meta` must be used. The structure differs,
though:

```rust
struct {
    status: u16,
    headers: Vec<(ByteString, ByteString)>,
}
```

The status code must be between 100 (inclusive) and 600 (exclusive), though
that is not checked immediately, but only when the response is sent (and will
cause an error).

The headers bear the same restrictions as described above.

This function can be used repeatedly: only the last write will be used when the
request is sent.

##### `(func (import "env" "read_body") (param i64) (result i32))`

Interpreted as `fn read_body(alloc: u64) -> i32`.

Reads as much as the request body is available, up to the allocation size.
Returns an I/O result.

The allocation should then be truncated to the length received from the result.

##### `(func (import "env" "write_body") (param i64) (result i32))`

Interpreted as `fn write_body(alloc: u64) -> i32`.

Writes the entire allocation to the response body stream. Returns an I/O result.

Writes will be buffered at least until the response metadata (headers etc) is
sent. (Currently, writes are buffered entirely, i.e. the response is not sent
at all until the wasm program run is finished. This may improve.)

#### Exports

There is only one export: the main / entry point.

##### `(func (export "slice_start"))`

This must be named `slice_start`.

It will be called exactly once per request.

Before it's called, the request meta blob will be prepared, such that the
`size_meta` and `read_meta` imports are always immediately available.

After it's called, the response meta blob will be parsed, the response body
buffer prepared, and the HTTP server will stream the response back along.