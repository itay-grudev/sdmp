# SDMP Reference Implementation

Secure Device Management Protocol Client, Server and Device Client reference
implementation.

## Requirements
    * `odb`
    * `gnutls`
    * `gnulib`
    * GNU `getopt` (with support for `getopt_long` available in the GNU implementation)

## Building

```bash
cmake ./
make
```

## License
Copyright Itay Grudev (c) 2019. Distributed under the terms of the GNU GPL v3 or later.

Portions of this software include code from other projects compatible with the
GNU GPL v3 license. Refer to the licensing information in the beginning of each
file. Full license list of all direct project dependencies can be found in the
`LICENSES` directory.
