//! Command-line parsing, by hand. Paths stay `OsString`: file names need not
//! be UTF-8.

use std::ffi::{OsStr, OsString};

use atlas_archive_core::name::NameEncoding;

/// A usage mistake, in a sentence (exit 2).
#[derive(Debug, PartialEq, Eq)]
pub struct Usage(pub String);

fn usage<T>(msg: impl Into<String>) -> Result<T, Usage> {
    Err(Usage(msg.into()))
}

/// The answer to a name clash that `--on-clash` gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnClash {
    Replace,
    Skip,
    KeepBoth,
}

/// What every command shares.
#[derive(Debug, PartialEq, Eq)]
pub struct Common {
    pub archive: OsString,
    pub json: bool,
    pub encoding: Option<NameEncoding>,
    /// A descriptor to read the password from.
    pub password_fd: Option<i32>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExtractArgs {
    pub common: Common,
    /// The folder to extract into; the archive's own folder when `None`.
    pub to: Option<OsString>,
    pub here: bool,
    pub name: Option<String>,
    pub entries: Vec<OsString>,
    pub allow_large: bool,
    pub on_clash: Option<OnClash>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    List(Common),
    Info(Common),
    Test(Common),
    Extract(ExtractArgs),
    Create,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub command: Command,
    /// `-v`: log to stderr.
    pub verbose: bool,
    /// `--worker PATH` (the `dev-worker` feature, tests only).
    #[cfg(feature = "dev-worker")]
    pub worker: Option<OsString>,
}

/// The options each command takes (besides the global ones).
fn allowed(command: &str) -> &'static [&'static str] {
    match command {
        "list" | "info" => &["--json", "--encoding", "--password-fd"],
        "test" => &["--json", "--password-fd"],
        "extract" => &[
            "--json",
            "--encoding",
            "--password-fd",
            "--to",
            "--here",
            "--name",
            "--allow-large",
            "--on-clash",
        ],
        _ => &[],
    }
}

/// Options that take a value.
fn takes_value(opt: &str) -> bool {
    matches!(
        opt,
        "--encoding" | "--password-fd" | "--to" | "--name" | "--on-clash"
    )
}

/// `--name` becomes the one folder made in the destination: a single
/// component, so it can't point anywhere else.
fn check_name(name: &str) -> Result<(), Usage> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return usage("--name must be one folder name, without a / in it.");
    }
    Ok(())
}

fn text<'a>(opt: &str, v: &'a OsStr) -> Result<&'a str, Usage> {
    match v.to_str() {
        Some(s) => Ok(s),
        None => usage(format!("The value of {opt} must be valid UTF-8.")),
    }
}

fn parse_fd(v: &OsStr) -> Result<i32, Usage> {
    let s = text("--password-fd", v)?;
    match s.parse::<i32>() {
        Ok(n) if n == 0 || n > 2 => Ok(n),
        Ok(1) | Ok(2) => usage("--password-fd can't be standard output or standard error."),
        _ => usage("--password-fd needs a file descriptor number."),
    }
}

/// Parses everything after the program name.
pub fn parse<I>(args: I) -> Result<Parsed, Usage>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let mut verbose = false;
    #[cfg_attr(not(feature = "dev-worker"), allow(unused_mut))]
    let mut worker: Option<OsString> = None;
    let mut command: Option<String> = None;

    // Options may come before the command; the first other word is it.
    let mut pending: Vec<OsString> = Vec::new();
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--") => {
                pending.extend(args.by_ref());
                break;
            }
            Some("-h" | "--help") => return Ok(done(Command::Help, verbose, worker)),
            Some("--version") => return Ok(done(Command::Version, verbose, worker)),
            Some("-v") => verbose = true,
            #[cfg(feature = "dev-worker")]
            Some(s) if s == "--worker" || s.starts_with("--worker=") => {
                let v = take_value("--worker", s, &mut args)?;
                worker = Some(v);
            }
            Some(s) if command.is_none() && !s.starts_with('-') => {
                command = Some(s.to_string());
                pending.extend(args.by_ref());
                break;
            }
            Some(s) if command.is_none() && s.starts_with('-') => {
                return usage(format!("Unknown option {}.", shown(&a)));
            }
            _ => return usage(format!("Unknown command {}.", shown(&a))),
        }
    }
    let Some(command) = command else {
        return usage("Say what to do: list, extract, test, info or create.");
    };
    let cmd = command.as_str();
    if !matches!(cmd, "list" | "extract" | "test" | "info" | "create") {
        return usage(format!("Unknown command {command}."));
    }
    if cmd == "create" {
        return Ok(done(Command::Create, verbose, worker));
    }

    let mut json = false;
    let mut encoding = None;
    let mut password_fd = None;
    let mut to = None;
    let mut here = false;
    let mut name = None;
    let mut allow_large = false;
    let mut on_clash = None;
    let mut positional: Vec<OsString> = Vec::new();

    // Options come before the archive, as with `git`: the first word that
    // isn't one, or a `--`, ends them, and everything after is a path. A
    // file called `--allow-large` reached by a glob is a path, not a flag.
    let mut rest = pending.into_iter();
    let mut options_done = false;
    while let Some(a) = rest.next() {
        let s = a.to_str();
        if options_done || s.is_none_or(|s| !s.starts_with('-') || s == "-") {
            options_done = true;
            positional.push(a);
            continue;
        }
        let s = s.unwrap_or_default();
        if s == "--" {
            options_done = true;
            continue;
        }
        let opt = s.split_once('=').map_or(s, |(o, _)| o);
        match opt {
            "-h" | "--help" => return Ok(done(Command::Help, verbose, worker)),
            "--version" => return Ok(done(Command::Version, verbose, worker)),
            "-v" => {
                verbose = true;
                continue;
            }
            #[cfg(feature = "dev-worker")]
            "--worker" => {
                worker = Some(take_value(opt, s, &mut rest)?);
                continue;
            }
            _ => {}
        }
        if !allowed(cmd).contains(&opt) {
            return usage(format!("Unknown option {} for {cmd}.", shown(&a)));
        }
        if !takes_value(opt) && s.contains('=') {
            return usage(format!("{opt} doesn't take a value."));
        }
        match opt {
            "--json" => json = true,
            "--here" => here = true,
            "--allow-large" => allow_large = true,
            _ => {
                let v = take_value(opt, s, &mut rest)?;
                match opt {
                    "--encoding" => {
                        let label = text(opt, &v)?;
                        match NameEncoding::from_label(label) {
                            Some(e) => encoding = Some(e),
                            None => {
                                return usage(format!(
                                    "Unknown name encoding {}.",
                                    crate::term::safe(label)
                                ));
                            }
                        }
                    }
                    "--password-fd" => password_fd = Some(parse_fd(&v)?),
                    "--to" => {
                        if v.is_empty() {
                            return usage("--to needs a folder.");
                        }
                        to = Some(v)
                    }
                    "--name" => {
                        let n = text(opt, &v)?;
                        check_name(n)?;
                        name = Some(n.to_string());
                    }
                    "--on-clash" => {
                        on_clash = Some(match text(opt, &v)? {
                            "replace" => OnClash::Replace,
                            "skip" => OnClash::Skip,
                            "keep-both" => OnClash::KeepBoth,
                            _ => return usage("--on-clash is replace, skip or keep-both."),
                        })
                    }
                    _ => unreachable!("every option with a value is handled"),
                }
            }
        }
    }

    if here && name.is_some() {
        return usage("--name can't be used with --here.");
    }
    let mut positional = positional.into_iter();
    let Some(archive) = positional.next() else {
        return usage(format!("{cmd} needs an archive."));
    };
    let entries: Vec<OsString> = positional.collect();
    if cmd != "extract" && !entries.is_empty() {
        return usage(format!("{cmd} takes one archive."));
    }
    let common = Common {
        archive,
        json,
        encoding,
        password_fd,
    };
    let command = match cmd {
        "list" => Command::List(common),
        "info" => Command::Info(common),
        "test" => Command::Test(common),
        _ => Command::Extract(ExtractArgs {
            common,
            to,
            here,
            name,
            entries,
            allow_large,
            on_clash,
        }),
    };
    Ok(done(command, verbose, worker))
}

fn done(command: Command, verbose: bool, worker: Option<OsString>) -> Parsed {
    #[cfg(not(feature = "dev-worker"))]
    let _ = worker;
    Parsed {
        command,
        verbose,
        #[cfg(feature = "dev-worker")]
        worker,
    }
}

/// The value of `opt`: after `=`, or the next argument.
fn take_value(
    opt: &str,
    arg: &str,
    rest: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, Usage> {
    if let Some((_, v)) = arg.split_once('=') {
        return Ok(OsString::from(v));
    }
    match rest.next() {
        Some(v) => Ok(v),
        None => usage(format!("{opt} needs a value.")),
    }
}

/// An argument in a message, made safe to show.
fn shown(a: &OsStr) -> String {
    crate::term::safe_os(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, Usage> {
        parse(args.iter().map(OsString::from))
    }

    fn cmd(args: &[&str]) -> Command {
        p(args).unwrap().command
    }

    fn err(args: &[&str]) -> String {
        p(args).unwrap_err().0
    }

    #[test]
    fn list_takes_an_archive_and_flags() {
        let Command::List(c) = cmd(&["list", "--json", "--encoding", "cp437", "a.zip"]) else {
            panic!()
        };
        assert_eq!(c.archive, "a.zip");
        assert!(c.json);
        assert_eq!(c.encoding, Some(NameEncoding::Cp437));
        assert_eq!(c.password_fd, None);
    }

    #[test]
    fn options_come_before_the_archive_and_use_equals() {
        let Command::List(c) = cmd(&["list", "--encoding=UTF-8", "--json", "x"]) else {
            panic!()
        };
        assert_eq!(c.archive, "x");
        assert_eq!(c.encoding, Some(NameEncoding::Utf8));
    }

    #[test]
    fn extract_collects_entries_and_options() {
        let Command::Extract(e) = cmd(&[
            "extract",
            "--to",
            "out",
            "--here",
            "--allow-large",
            "--on-clash=skip",
            "--password-fd",
            "3",
            "a.zip",
            "one",
            "two/three",
        ]) else {
            panic!()
        };
        assert_eq!(e.to.as_deref(), Some(OsStr::new("out")));
        assert!(e.here && e.allow_large);
        assert_eq!(e.entries, ["one", "two/three"]);
        assert_eq!(e.on_clash, Some(OnClash::Skip));
        assert_eq!(e.common.password_fd, Some(3));
    }

    #[test]
    fn name_conflicts_with_here() {
        assert!(err(&["extract", "--here", "--name", "x", "a.zip"]).contains("--here"));
        assert!(matches!(
            cmd(&["extract", "--name", "x", "a.zip"]),
            Command::Extract(_)
        ));
    }

    #[test]
    fn unknown_options_and_commands_are_refused() {
        assert!(err(&["list", "--bogus", "a.zip"]).contains("Unknown option --bogus"));
        assert!(err(&["list", "--here", "a.zip"]).contains("Unknown option --here for list"));
        assert!(err(&["test", "--encoding", "utf-8", "a.zip"]).contains("Unknown option"));
        assert!(err(&["frobnicate"]).contains("Unknown command"));
        assert!(err(&["--frob"]).contains("Unknown option"));
        assert!(err(&[]).contains("Say what to do"));
    }

    #[test]
    fn missing_archive_or_value_is_refused() {
        assert!(err(&["list"]).contains("needs an archive"));
        assert!(err(&["extract", "--to"]).contains("needs a value"));
        assert!(err(&["list", "a", "b"]).contains("takes one archive"));
    }

    #[test]
    fn values_are_checked() {
        assert!(err(&["list", "--encoding", "klingon", "a"]).contains("Unknown name encoding"));
        assert!(err(&["extract", "--on-clash", "maybe", "a"]).contains("--on-clash"));
        assert!(err(&["test", "--password-fd", "x", "a"]).contains("descriptor"));
        assert!(err(&["test", "--password-fd", "-4", "a"]).contains("descriptor"));
        assert!(err(&["test", "--password-fd", "1", "a"]).contains("standard output"));
        assert!(err(&["list", "--json=yes", "a"]).contains("doesn't take a value"));
        assert!(matches!(
            cmd(&["test", "--password-fd", "0", "a"]),
            Command::Test(_)
        ));
    }

    #[test]
    fn help_version_and_create() {
        assert_eq!(cmd(&["--help"]), Command::Help);
        assert_eq!(cmd(&["list", "-h", "a"]), Command::Help);
        assert_eq!(cmd(&["--version"]), Command::Version);
        assert_eq!(cmd(&["create", "a", "b"]), Command::Create);
    }

    #[cfg(feature = "dev-worker")]
    #[test]
    fn global_options_work_before_the_archive() {
        let r = p(&["--worker", "/w", "-v", "list", "a.zip"]).unwrap();
        assert_eq!(r.worker.as_deref(), Some(OsStr::new("/w")));
        assert!(r.verbose);
        let r = p(&["list", "--worker=/x", "a.zip"]).unwrap();
        assert_eq!(r.worker.as_deref(), Some(OsStr::new("/x")));
    }

    #[cfg(not(feature = "dev-worker"))]
    #[test]
    fn worker_is_not_an_option_in_a_normal_build() {
        for args in [
            &["--worker=x", "list", "a.zip"][..],
            &["--worker", "x", "list", "a.zip"],
            &["list", "--worker=x", "a.zip"],
            &["extract", "--worker", "x", "a.zip"],
        ] {
            assert!(err(args).contains("Unknown option"), "{args:?}");
        }
        // After the archive it is just another path.
        let Command::Extract(e) = cmd(&["extract", "a.zip", "--worker=x"]) else {
            panic!()
        };
        assert_eq!(e.entries, ["--worker=x"]);
    }

    #[test]
    fn the_first_path_ends_the_options() {
        // A glob that expands to file names that look like flags.
        let Command::Extract(e) = cmd(&["extract", "a.zip", "--allow-large", "--to=/x", "-v"])
        else {
            panic!()
        };
        assert!(!e.allow_large && e.to.is_none());
        assert_eq!(e.entries, ["--allow-large", "--to=/x", "-v"]);
        let Command::Test(c) = cmd(&["test", "--json", "--", "--allow-large"]) else {
            panic!()
        };
        assert!(c.json);
        assert_eq!(c.archive, "--allow-large");
        assert!(err(&["test", "a.zip", "b.zip"]).contains("takes one"));
    }

    #[test]
    fn name_is_one_component() {
        for bad in ["", ".", "..", "a/b", "/abs", "../x", "a\0b"] {
            assert!(
                err(&["extract", "--name", bad, "a.zip"]).contains("--name"),
                "{bad:?}"
            );
        }
        assert!(matches!(
            cmd(&["extract", "--name=my folder", "a.zip"]),
            Command::Extract(_)
        ));
    }

    #[test]
    fn double_dash_ends_options() {
        let Command::Extract(e) = cmd(&["extract", "--", "-a.zip", "--json"]) else {
            panic!()
        };
        assert_eq!(e.common.archive, "-a.zip");
        assert_eq!(e.entries, ["--json"]);
        assert!(!e.common.json);
    }

    #[test]
    fn non_utf8_paths_are_kept() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let bad = OsString::from_vec(vec![b'a', 0xff, b'.', b'z']);
        let r = parse([OsString::from("list"), bad.clone()]).unwrap();
        let Command::List(c) = r.command else {
            panic!()
        };
        assert_eq!(c.archive.as_bytes(), bad.as_bytes());
        let r = parse([OsString::from("extract"), OsString::from("a"), bad.clone()]).unwrap();
        let Command::Extract(e) = r.command else {
            panic!()
        };
        assert_eq!(e.entries, [bad]);
    }
}
