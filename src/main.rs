// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

mod op;
mod pinentry;

use std::io::{self, BufRead};

use op::ItemRef;
use pinentry::Session;

fn main() -> io::Result<()> {
    let mut session = Session::new(
        ItemRef::load()?,
        io::stdout().lock()
    );

    session.announce()?;

    for req in io::stdin().lock().lines() {
        if !session.handle(&*req?)? { break }
    }

    Ok(())
}
