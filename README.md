# SDMP Reference Implementation
Secure Device Management Protocol Client, Server and Device Client reference
implementation.

The Secure Device Management Protocol (SDMP) allows messaging and management of mobile devices to allows operations like remotely ringing, tracking, locking or erasing your device. Mobile devices are often connected through WiFi or cellular data with intermittent connectivity and behind NAT or a firewall, so to go around that the protocol employs a relay server. However with an innovative approach and end-to-end encryption the protocol prevents the relay server from reading messages or impersonating the user. A key feature of the protocol is that it uses a single password used for both authentication with the relay server and the end-to-end encryption. This password is never shared with the relay server during authentication by employing the Stanford Remote Password (SRP) protocol which allows the same password to be used for encryption of the communication.

## Requirements
    * `libodb-dev`
    * `gnutls`
    * `gnulib`
    * GNU `getopt` (with support for `getopt_long` available in the GNU implementation)
    * `cppcheck`
    * `libpistache-dev`

## Building

```bash
cmake ./
make static-resources # see sdmp-server/CMakeLists.txt
make ssl-cert # see sdmp-server/CMakeLists.txt
make
```

## License
Copyright Itay Grudev (c) 2019. Distributed under the terms of the GNU GPL v3 or later.

Portions of this software include code from other projects compatible with the
GNU GPL v3 license. Refer to the licensing information in the beginning of each
file. Full license list of all direct project dependencies can be found in the
`LICENSES` directory.
