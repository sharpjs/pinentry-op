// Copyright Jeffrey Sharp
// SPDX-License-Identifier: ISC

// References:
// https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
// https://www.gnupg.org/documentation/manuals/assuan/
// https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi
// https://github.com/gpg/pinentry/blob/master/pinentry/pinentry.c
// https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in
// https://github.com/gpg/libgpg-error/blob/master/doc/errorref.txt
// https://developer.1password.com/docs/cli/reference/commands/read
// https://developer.1password.com/docs/cli/reference/management-commands/item

use std::io::{self, Write};
use std::process::{self, Command};

const FLAVOR:  &str = "op";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub struct Session<'a, O: Write> {
    out:      O,
    item_ref: &'a str,
    cache_ok: bool,
}

impl<'a, O: Write> Session<'a, O> {
    pub fn new(item_ref: &'a str, out: O) -> Self {
        Self { out, item_ref, cache_ok: false }
    }

    pub fn announce(&mut self) -> io::Result<()> {
        if cfg!(debug_assertions) {
            writeln!(self.out, "# pinentry-op v0.1.0")?;
            writeln!(self.out, "# passphrase: {}", self.item_ref)?;
        }
        writeln!(self.out, "OK pinentry-op ready")
    }

    pub fn handle(&mut self, line: &str) -> io::Result<bool> {
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
        writeln!(self.out, "# BYE")?;
        writeln!(self.out, "# GETINFO {{ flavor | version | pid | ttyinfo }}")?;
        writeln!(self.out, "# GETPIN")?;
        writeln!(self.out, "# HELP")?;
        writeln!(self.out, "# OPTION <name> [ [=] <value> ]")?;
        writeln!(self.out, "# RESET")?;
        writeln!(self.out, "OK")?;
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
        let pin = get_pin(&self.item_ref)?;
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

fn get_pin(item_ref: &str) -> io::Result<String> {
    use io::{Error, ErrorKind};

    let result = Command::new("op").arg("read").arg(item_ref).output()?;

    if !result.status.success() {
        return Err(Error::new(ErrorKind::Other, "1Password CLI encountered an error"));
    }

    if result.stdout.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "1Password CLI returned empty data"));
    }

    let mut pin = match String::from_utf8(result.stdout) {
        Ok (s) => s,
        Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
    };

    pin.retain(is_not_ascii_newline);

    Ok(pin)
}

fn is_not_ascii_newline(c: char) -> bool {
    !matches!(c, '\r' | '\n')
}

#[cfg(test)]
mod tests {
    use std::str;
    use super::*;

    #[test]
    fn bye() {
        with_session()
        .test("BYE any", false, "OK closing connection\n");
    }

    #[derive(Debug)]
    struct Harness(Session<'static, Vec<u8>>);

    fn with_session() -> Harness {
        Harness(Session::new("test", vec![]))
    }

    impl Harness {
        fn test(mut self, input: &str, result: bool, output: &str) -> Self {
            let res = self.0.handle(input).unwrap();
            let out = str::from_utf8(&self.0.out[..]).unwrap();

            assert_eq!(res, result);
            assert_eq!(out, output);

            self.0.out.clear();
            self
        }
    }
}
