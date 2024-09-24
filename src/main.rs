// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

mod op;
mod pinentry;

use std::io::{self, BufRead};

use pinentry::Session;

fn main() -> io::Result<()> {
    let mut session = Session::new(
        op::get_item_ref()?,
        io::stdout().lock()
    );

    session.announce()?;

    for req in io::stdin().lock().lines() {
        if !session.handle(&*req?)? { break }
    }

    Ok(())
}
