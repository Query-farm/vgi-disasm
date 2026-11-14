# Static fixture provenance

`hello-macho-arm64.bin` is an unchanged copy of the repository's committed
`test/sql/data/hello-macho-arm64` at source revision
`cb7d007ae870f12ffc6350d8bdb7291ec1e97077`.
It is the existing ARM64 Mach-O hello-world test fixture, used strictly as data.
The notebook never executes, recompiles or modifies it.

Size: 49,952 bytes. SHA-256: `da58bb1fa4b6b7d85b829a1b650024c103fd0182a98eef19b9e0b78b43c06239`.
The `.bin` companion has no executable bit. The release parser exposes eight
sections and two imports; the notebook explains those scopes explicitly.

The text control is authored inline in the visible SQL and is separate from this
container. No binary or control is downloaded from a malware corpus.
