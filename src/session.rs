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
use std::process::Command;

#[derive(Debug)]
pub struct Session<O: Write> {
    out:      O,
    cache_ok: bool,
}

impl<O: Write> Session<O> {
    pub fn new(out: O) -> Self {
        Self { out, cache_ok: false }
    }

    pub fn announce(&mut self) -> io::Result<()> {
        writeln!(self.out, "OK pinentry-op ready")
    }

    pub fn handle(&mut self, line: &str) -> io::Result<bool> {
        let (cmd, rest) = match line.split_once(' ') {
            Some(pair) => pair,
            None       => (line, ""),
        };

        let ret = match cmd.to_ascii_uppercase().as_str() {
            "BYE"        => self.handle_bye    (),
            "RESET"      => self.handle_nop    (), // TODO
            "HELP"       => self.handle_nop    (), // TODO
            "OPTION"     => self.handle_option (rest),
            "GETINFO"    => self.handle_nop    (), // TODO
            "SETKEYINFO" => self.handle_nop    (), // TODO
            "SETDESC"    => self.handle_nop    (), // TODO
            "SETPROMPT"  => self.handle_nop    (), // TODO
            "GETPIN"     => self.handle_getpin (),
            "FOO"        => self.handle_unknown(),
            _            => self.handle_ignored(),
        };

        self.out.flush()?;
        ret
    }

    fn handle_nop(&mut self) -> io::Result<bool> {
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_ignored(&mut self) -> io::Result<bool> {
        writeln!(self.out, "OK ignored command")?;
        Ok(true)
    }

    fn handle_unknown(&mut self) -> io::Result<bool> {
        writeln!(self.out, "ERR 275 unsupported command")?;
        Ok(true)
    }

    fn handle_option(&mut self, rest: &str) -> io::Result<bool> {
        match rest.to_ascii_lowercase().as_str() {
            "allow-external-password-cache" => { self.cache_ok = true },
            _                               => { },
        }
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_getpin(&mut self) -> io::Result<bool> {
        let pin = get_pin()?;
        if self.cache_ok {
            writeln!(self.out, "S PASSWORD_FROM_CACHE")?;
        }
        writeln!(self.out, "D {}", pin)?;
        writeln!(self.out, "OK")?;
        Ok(true)
    }

    fn handle_bye(&mut self) -> io::Result<bool> {
        writeln!(self.out, "OK closing connection")?;
        Ok(false)
    }
}

fn get_pin() -> io::Result<String> {
    use io::{Error, ErrorKind};

    let result = Command::new("op")
        .arg("read")
        .arg("op://(vaultid)/(itemid)/password")
        .output()?;

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
