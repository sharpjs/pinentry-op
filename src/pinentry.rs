// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

// References:
// https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
// https://www.gnupg.org/documentation/manuals/assuan/
// https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi
// https://github.com/gpg/pinentry/blob/master/pinentry/pinentry.c
// https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in
// https://github.com/gpg/libgpg-error/blob/master/doc/errorref.txt
// https://developer.1password.com/docs/cli/reference/commands/read
// https://developer.1password.com/docs/cli/reference/management-commands/item

use std::fmt::Debug;
use std::io::{self, BufRead, Write};
use std::process;

const FLAVOR:  &str = "op";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const HELP:    &str = "\
    # BYE\n\
    # GETINFO { flavor | version | pid | ttyinfo }\n\
    # GETPIN\n\
    # HELP\n\
    # OPTION <name> [ [=] <value> ]\n\
    # RESET\n\
    OK\n\
";

pub trait Secret: Debug {
    fn read(&self) -> io::Result<String>;
}

#[derive(Debug)]
pub struct Session<S: Secret, O: Write> {
    out:      O,
    secret:   S,
    cache_ok: bool,
}

impl<S: Secret, O: Write> Session<S, O> {
    pub fn new(secret: S, out: O) -> Self {
        Self { out, secret, cache_ok: false }
    }

    pub fn run<I: BufRead>(&mut self, input: I) -> io::Result<()> {
        self.announce()?;

        for req in input.lines() {
            if !self.handle(&*req?)? { break }
        }

        Ok(())
    }

    fn announce(&mut self) -> io::Result<()> {
        #[cfg(all(debug_assertions, not(test)))]
        writeln!(self.out, "# secret: {:?}", self.secret)?;
        writeln!(self.out, "OK pinentry-op ready")
    }

    fn handle(&mut self, line: &str) -> io::Result<bool> {
        use State::*;

        enum State {
            Initial,
            B, By, Bye,
            G, Ge, Get, Geti, Getin, Getinf, Getinfo,
                        Getp, Getpi, Getpin,
            H, He, Hel, Help,
            O, Op, Opt, Opti, Optio, Option,
            R, Re, Res, Rese, Reset,
        }

        let mut chars = line.chars();
        let mut state = Initial;

        let ret = loop {
            let c = chars.next().unwrap_or(' ').to_ascii_uppercase();
            state = match (state, c) {
                (Initial, 'B') => B,
                (B,       'Y') => By,
                (By,      'E') => Bye,
                (Bye,     ' ') => break self.handle_bye(),

                (Initial, 'G') => G,
                (G,       'E') => Ge,
                (Ge,      'T') => Get,
                (Get,     'I') => Geti,
                (Geti,    'N') => Getin,
                (Getin,   'F') => Getinf,
                (Getinf,  'O') => Getinfo,
                (Getinfo, ' ') => break self.handle_getinfo(chars.as_str()),

                (Get,     'P') => Getp,
                (Getp,    'I') => Getpi,
                (Getpi,   'N') => Getpin,
                (Getpin,  ' ') => break self.handle_getpin(),

                (Initial, 'H') => H,
                (H,       'E') => He,
                (He,      'L') => Hel,
                (Hel,     'P') => Help,
                (Help,    ' ') => break self.handle_help(),

                (Initial, 'O') => O,
                (O,       'P') => Op,
                (Op,      'T') => Opt,
                (Opt,     'I') => Opti,
                (Opti,    'O') => Optio,
                (Optio,   'N') => Option,
                (Option,  ' ') => break self.handle_option(chars.as_str()),

                (Initial, 'R') => R,
                (R,       'E') => Re,
                (Re,      'S') => Res,
                (Res,     'E') => Rese,
                (Rese,    'T') => Reset,
                (Reset,   ' ') => break self.handle_reset(),

                _              => break self.handle_nop(),
            };
        };

        self.out.flush()?;
        ret
    }

    fn handle_nop(&mut self) -> io::Result<bool> {
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_help(&mut self) -> io::Result<bool> {
        write!(self.out, "{}", HELP)?;
        Ok(true)
    }

    fn handle_getinfo(&mut self, arg: &str) -> io::Result<bool> {
        let c = arg.chars().nth(0).unwrap_or_default().to_ascii_lowercase();
        match c {
            'f' if arg.eq_ignore_ascii_case("flavor") => {
                writeln!(self.out, "D {}", FLAVOR)?
            },
            'v' if arg.eq_ignore_ascii_case("version") => {
                writeln!(self.out, "D {}", VERSION)?
            },
            'p' if arg.eq_ignore_ascii_case("pid") => {
                writeln!(self.out, "D {}", process::id())?
            },
            't' if arg.eq_ignore_ascii_case("ttyinfo") => {
                writeln!(self.out, "D - - - - 0/0 -")?
            },
            _ => (),
        }
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_option(&mut self, arg: &str) -> io::Result<bool> {
        if arg.eq_ignore_ascii_case("allow-external-password-cache") {
            self.cache_ok = true
        }
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_getpin(&mut self) -> io::Result<bool> {
        let pin = self.secret.read()?;
        if self.cache_ok {
            writeln!(self.out, "S PASSWORD_FROM_CACHE")?;
        }
        writeln!(self.out, "D {}", pin)?;
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_reset(&mut self) -> io::Result<bool> {
        self.cache_ok = false;
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_bye(&mut self) -> io::Result<bool> {
        writeln!(self.out, "OK closing connection")?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::str;
    use super::*;

    #[test]
    fn announce() {
        with_session()
            .test_announce("OK pinentry-op ready\n")
        ;
    }

    #[test]
    fn bye() {
        with_session()
            .test_handle_ok("Bye", false, "OK closing connection\n")
        ;
    }

    #[test]
    fn getinfo() {
        with_session()
            .test_handle_ok("GetInfo",         true, "OK\n")
            .test_handle_ok("GetInfo Other",   true, "OK\n")
            .test_handle_ok("GetInfo Version", true, format!("D {}\nOK\n", VERSION))
            .test_handle_ok("GetInfo Flavor" , true, format!("D {}\nOK\n", FLAVOR))
            .test_handle_ok("GetInfo Pid",     true, format!("D {}\nOK\n", process::id()))
            .test_handle_ok("GetInfo TtyInfo", true, "D - - - - 0/0 -\nOK\n")
        ;
    }

    #[test]
    fn getpin_ok() {
        with_session()
            .set_secret(Some(Ok(())))
            .test_handle_ok("GETPIN", true, "D test-pin\nOK\n")
        ;
    }

    #[test]
    fn getpin_ok_cached() {
        with_session()
            .set_cache_ok(true)
            .set_secret(Some(Ok(())))
            .test_handle_ok("GETPIN", true, "S PASSWORD_FROM_CACHE\nD test-pin\nOK\n")
        ;
    }

    #[test]
    fn getpin_err() {
        with_session()
            .set_secret(Some(Err(())))
            .test_handle_err("GETPIN")
        ;
    }

    #[test]
    fn help() {
        with_session()
            .test_handle_ok("Help", true, HELP)
        ;
    }

    #[test]
    fn option_cache_ok() {
        with_session()
            .set_cache_ok(false)
            .test_handle_ok("Option Allow-External-Password-Cache", true, "OK\n")
            .assert_cache_ok(true)
        ;
    }

    #[test]
    fn option_other() {
        with_session()
            .set_cache_ok(false)
            .test_handle_ok("Option Other", true, "OK\n")
            .assert_cache_ok(false)
        ;
    }

    #[test]
    fn reset() {
        with_session()
            .set_cache_ok(true)
            .test_handle_ok("Reset", true, "OK\n")
            .assert_cache_ok(false)
        ;
    }

    #[test]
    fn other() {
        with_session()
            .test_handle_ok("Other", true, "OK\n")
        ;
    }

    type TestSecret  = Option<Result<(), ()>>;
    type TestSession = Session<TestSecret, Vec<u8>>;

    impl Secret for TestSecret {
        fn read(&self) -> io::Result<String> {
            match self.unwrap() {
                Ok (_) => Ok("test-pin".to_string()),
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Test error.")),
            }
        }
    }

    struct Harness(TestSession);

    fn with_session() -> Harness {
        Harness(TestSession::new(None, vec![]))
    }

    impl Harness {
        fn set_cache_ok(&mut self, v: bool) -> &mut Self {
            self.0.cache_ok = v;
            self
        }

        fn set_secret(&mut self, v: TestSecret) -> &mut Self {
            self.0.secret = v;
            self
        }

        fn test_announce<O: AsRef<str>>(&mut self, output: O) -> &mut Self {
            self.0.announce().unwrap();
            self.assert_output(output)
        }

        fn test_handle_ok<O: AsRef<str>>(&mut self, input: &str, result: bool, output: O) -> &mut Self {
            let res = self.0.handle(input).unwrap();
            assert_eq!(res, result);
            self.assert_output(output)
        }

        fn test_handle_err(&mut self, input: &str) -> &mut Self {
            assert!(self.0.handle(input).is_err());
            self.assert_output("")
        }

        fn assert_output<O: AsRef<str>>(&mut self, exp: O) -> &mut Self {
            let actual = str::from_utf8(&self.0.out[..]).unwrap();
            assert_eq!(actual, exp.as_ref());
            self.0.out.clear();
            self
        }

        fn assert_cache_ok(&mut self, exp: bool) -> &mut Self {
            assert_eq!(self.0.cache_ok, exp);
            self
        }
    }
}
