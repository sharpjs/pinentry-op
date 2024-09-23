// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

mod op;
mod pinentry;

use std::env;
use std::fs;
use std::io::{self, BufRead};

use pinentry::Session;

fn main() -> io::Result<()> {
    let     item_ref = get_item_ref()?;
    let mut session  = Session::new(&item_ref, io::stdout().lock());

    session.announce()?;

    for req in io::stdin().lock().lines() {
        if !session.handle(&*req?)? { break }
    }

    Ok(())
}

fn get_item_ref() -> io::Result<String> {
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
