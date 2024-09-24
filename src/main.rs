// Copyright Jeffrey Sharp
// SPDX-License-Identifier: MIT

mod op;
mod pinentry;

use std::io;
use pinentry::Session;

fn main() -> io::Result<()> {
    let mut session = Session::new(
        op::get_item_ref()?,
        io::stdout().lock()
    );

    session.run(io::stdin().lock())
}
