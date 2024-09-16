// Copyright Jeffrey Sharp
// SPDX-License-Identifier: ISC

mod session;

use std::io::{self, BufRead};
use crate::session::*;

fn main() -> io::Result<()> {
    let mut session = Session::new(io::stdout().lock());

    session.announce()?;

    for req in io::stdin().lock().lines() {
        if !session.handle(&*req?)? { break }
    }

    Ok(())
}
