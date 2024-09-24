// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

use std::fmt::Debug;
use std::io::{self, Error, ErrorKind};
use std::process::{Command, Output};
use crate::pinentry::Secret;

#[derive(Debug)]
pub struct ItemRef<S: AsRef<str>>(S);

impl<S: AsRef<str>> ItemRef<S> {
    pub fn new(s: S) -> Self {
        Self(s)
    }
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
