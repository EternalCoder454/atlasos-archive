//! Atlas Archive's core: no Qt and no archive parser. Everything here works
//! on data that came from an archive, through the sandboxed worker, and
//! treats it as untrusted (docs/DESIGN.md, "Extraction rules" and "Names").

pub mod audit;
pub mod client;
pub mod limits;
pub mod link;
pub mod name;
pub mod path;
pub mod proto;
pub mod tree;
