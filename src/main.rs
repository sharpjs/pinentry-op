// Copyright Jeffrey Sharp
// SPDX-License-Identifier: ISC

// References:
// https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
// https://www.gnupg.org/documentation/manuals/assuan/
// https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi
// https://github.com/gpg/libgpg-error/blob/master/src/err-codes.h.in
// https://github.com/gpg/libgpg-error/blob/master/doc/errorref.txt
// https://developer.1password.com/docs/cli/reference/commands/read
// https://developer.1password.com/docs/cli/reference/management-commands/item

use std::io::{self, BufRead, Write};
use std::process::Command;

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();

    writeln!(out, "OK pinentry-op ready")?;

    for req in io::stdin().lock().lines() {
        if !handle(req?.as_str(), &mut out)? { break }
    }

    out.flush()?;
    Ok(())
}

fn handle<O: Write>(req: &str, out: &mut O) -> io::Result<bool> {
    let (cmd, _) = match req.split_once(' ') {
        Some(pair) => pair,
        None       => (req, ""),
    };

    match cmd.to_ascii_uppercase().as_str() {
        "GETPIN" => handle_getpin (out),
        "BYE"    => handle_bye    (out),
        "NOP"    => handle_nop    (out),
        "FOO"    => handle_unknown(out),
        _        => handle_ignored(out),
    }
}

fn handle_bye<O: Write>(out: &mut O) -> io::Result<bool> {
    writeln!(out, "OK closing connection")?;
    Ok(false)
}

fn handle_ignored<O: Write>(out: &mut O) -> io::Result<bool> {
    writeln!(out, "OK ignored command")?;
    Ok(true)
}

fn handle_unknown<O: Write>(out: &mut O) -> io::Result<bool> {
    writeln!(out, "ERR 275 unsupported command")?;
    Ok(true)
}

fn handle_getpin<O: Write>(out: &mut O) -> io::Result<bool> {
    let pin = get_pin()?;
    writeln!(out, "D {}", pin)?;
    writeln!(out, "OK")?;
    Ok(true)
}

fn handle_nop<O: Write>(out: &mut O) -> io::Result<bool> {
    writeln!(out, "OK")?;
    Ok(true)
}

fn get_pin() -> io::Result<String> {
    use io::{Error, ErrorKind};

    let result = Command::new("op")
        .arg("read") 
        .arg("op://(vaultId)/(itemId)/password")
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
