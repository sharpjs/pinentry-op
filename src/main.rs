// Copyright Jeffrey Sharp
// SPDX-License-Identifier: ISC

// References:
// https://github.com/gpg/pinentry/blob/master/doc/pinentry.texi
// https://developer.1password.com/docs/cli/reference/commands/read
// https://developer.1password.com/docs/cli/reference/management-commands/item
// https://www.gnupg.org/documentation/manuals/gnupg/Agent-Options.html
// https://www.gnupg.org/documentation/manuals/assuan/
// https://github.com/Chronic-Dev/libgpg-error/blob/master/src/err-codes.h.in
// https://github.com/Chronic-Dev/libgpg-error/blob/master/doc/errorref.txt

use std::{
    fs, io::{self, BufRead, BufWriter, Write}, process::Command
};

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    let mut log = io::empty(); // BufWriter::new(fs::File::create("pinentry-op.log")?);

    writeln!(out, "OK pinentry-op ready")?;
    writeln!(log, "O: OK pinentry-op ready")?;

    for request in io::stdin().lock().lines() {
        if !handle(request?.as_str(), &mut out, &mut log)? { break }
    }

    out.flush()?;
    log.flush()?;

    Ok(())
}

fn handle<O, L>(req: &str, out: &mut O, log: &mut L) -> io::Result<bool>
    where O: Write, L: Write
{
    writeln!(log, "---")?;
    writeln!(log, "I: {}", req)?;

    let (cmd, _) = match req.split_once(' ') {
        Some(pair) => pair,
        None       => (req, ""),
    };

    match cmd {
        "GETPIN" => handle_getpin (out, log),
        "BYE"    => handle_bye    (out, log),
        "FOO"    => handle_unknown(out, log),
        _        => handle_ignored(out, log),
    }
}

fn handle_bye<O, L>(out: &mut O, log: &mut L) -> io::Result<bool>
where O: Write, L: Write
{
    writeln!(out,    "OK closing connection")?;
    writeln!(log, "O: OK closing connection")?;
    Ok(false)
}

fn handle_ignored<O, L>(out: &mut O, log: &mut L) -> io::Result<bool>
where O: Write, L: Write
{
    writeln!(out,    "OK ignored command")?;
    writeln!(log, "O: OK ignored command")?;
    Ok(true)
}

fn handle_unknown<O, L>(out: &mut O, log: &mut L) -> io::Result<bool>
where O: Write, L: Write
{
    writeln!(out,    "ERR 275 unsupported command")?;
    writeln!(log, "O: ERR 275 unsupported command")?;
    Ok(true)
}

fn handle_getpin<O, L>(out: &mut O, log: &mut L) -> io::Result<bool>
where O: Write, L: Write
{
    let pin = get_pin()?;

    writeln!(out,    "D {}", pin         )?;
    writeln!(log, "O: D {}", "(redacted)")?;

    writeln!(out,    "OK")?;
    writeln!(log, "O: OK")?;

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

