// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

use std::env;
use std::fmt::Debug;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::process::{Command, Output};
use crate::pinentry::Secret;

#[derive(Debug)]
pub struct ItemRef<S: AsRef<str>>(S);

impl ItemRef<String> {
    pub fn load() -> io::Result<Self> {
        Ok(Self(get_item_ref()?))
    }
}

pub fn get_item_ref() -> io::Result<String> {
    // Get configuration file path
    let mut path = env::current_exe()?;
    path.set_extension("cfg");

    // Read configuration file
    let mut cfg = fs::read_to_string(path)?;

    // Truncate configuration to first newline
    let len = cfg.find(is_newline).unwrap_or_else(|| cfg.len());
    cfg.truncate(len);

    // The 'configuration' is a 1P item reference to the GPG passphrase
    Ok(cfg)
}

fn is_newline(c: char) -> bool {
    matches!(c, '\n' | '\r')
}

impl<S: AsRef<str> + Debug> Secret for ItemRef<S> {
    fn read(&self) -> io::Result<String> {
        get_pin(self.0.as_ref(), Command::output)
    }
}

type CommandRunner = fn(&mut Command) -> io::Result<Output>;

pub fn get_pin(item_ref: &str, run: CommandRunner) -> io::Result<String> {
    let result = run(Command::new("op").arg("read").arg(item_ref))?;

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
    !matches!(c, '\n' | '\r')
}
