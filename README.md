# pinentry-op

A quickly-thrown-together GPG pinentry program that knows only how to retrieve
a predetermined passphrase from 1Password.

## Installation

There is no easy installer yet.  There might never be one.

- Ensure prerequisites are installed: GPG, 1Password, 1Password CLI.

- Build.

  ```sh
  cargo build --release
  ```

- Create a file `pinentry-op.cfg` in the same directory as the binary.  The
  content of the file should be the 1Password item reference of the passphrase.
  For example:

  ```
  op://MyVault/MyItem/password
  ```

- Edit `gpg-agent.conf` to point to the binary.

  ```properties
  pinentry-program D:\Code\Self\pinentry-op\target\release\pinentry-op.exe
  ```

# Testing

Run this:

```sh
echo "" > test.txt
gpgconf --reload gpg-agent
gpg --sign --dry-run --yes test.txt
```

1Password should prompt to authorize gpg-agent for CLI access.

![1Password authorization prompt screenshot](https://github.com/sharpjs/pinentry-op/blob/main/doc/op-prompt.png?raw=true)

<!--
Copyright Jeffrey Sharp
SPDX-License-Identifier: MIT
-->
