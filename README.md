# wireshark-plugin

Wireshark/tshark Plugin in C for [RSocket](https://github.com/ReactiveSocket/reactivesocket).

NOTE: This is a work in progress.

Currently it supports all RSocket frames, except resumption.

# Build

- Download Wireshark source-code.
- Create __rsocket__ directory inside __wireshark/plugins__ folder.
- Download/Clone source code from this repo into the __rsocket__ folder.
- Inside __wireshark__ folder, create __CMakeListsCustom.txt__ and add the line.
```
set(CUSTOM_PLUGIN_SRC_DIR plugins/epan/rsocket)
```
- Follow the build instructions of Wireshark for your OS setup
- Copy the built rsocket.so to the Plugins folder of wireshark. This depends on OS - on macOS it is typically ~/.config/wireshark/plugins or ~/.wireshark/plugins.

# Notes

- This code has been tested with latest stable release of Wireshark (2.2.5).
- To enable RSocket dissector in Wireshark, go to __Analyze -> Decode As__ in Wireshark UI and add identifiers for your packet flow (say TCP port). Select RSocket as the decoding protocol.

