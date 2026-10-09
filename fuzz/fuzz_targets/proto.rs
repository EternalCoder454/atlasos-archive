#![no_main]
//! What the worker sends back is untrusted: the client's parser sees whatever
//! a compromised reader writes. Requests are parsed by the worker from the
//! client's pipe (trusted), but must never panic either.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use telamon_archive_core::proto::{self, Reply, Request};

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Reply::decode(data) {
        // What it accepted, it writes the same way.
        let again = Reply::decode(&r.encode()).expect("an encoded reply decodes");
        assert_eq!(again.encode(), r.encode());
    }
    let _ = Request::decode(data);
    // and through the frame reader: the length prefix is untrusted too
    let mut cur = Cursor::new(data);
    while let Ok(Some(frame)) = proto::read_frame(&mut cur) {
        assert!(frame.len() <= proto::MAX_FRAME);
        let _ = Reply::decode(&frame);
    }
});
