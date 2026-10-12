# Acknowledgements

AliceSoundFetcher is licensed under the Apache License, Version 2.0 — see
[`LICENSE.txt`](LICENSE.txt). It also relies on, or was developed with the help
of, the third-party software listed below.

## Summary

| Project | Licence | Relationship to this project |
| --- | --- | --- |
| [MinHook](https://github.com/TsudaKageyu/minhook) | BSD 2-Clause | Link-time dependency (x86 binaries in `external/`) |
| [alice-tools](https://github.com/nunuhara/alice-tools) | GPL-2.0 | **Verification only — not linked, not vendored, not redistributed** |
| [Windows SDK Debuggers](https://learn.microsoft.com/windows-hardware/drivers/debugger/) | Microsoft | Diagnostic tooling |
| [Microsoft Visual C++](https://learn.microsoft.com/cpp/) | Microsoft | Build toolchain |
| DEFLATE / zlib format (RFC 1950, RFC 1951) | zlib (format spec) | Format reference only — implementation is our own |

---

## MinHook — BSD 2-Clause

MinHook is used for function hooking infrastructure in the injected DLL. The x86
headers and import libraries are placed under `external/minhook/` by hand; that
directory is git-ignored and is **not** redistributed in this repository.
Redistributing a build that links it requires reproducing the notice below, which
is why it is included here in full (BSD 2-Clause, clause 2).

```
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## alice-tools — GPL-2.0

**This project is GPL-2.0 licensed while AliceSoundFetcher is Apache-2.0, so how
it is used here matters. Read this before copying anything across.**

alice-tools (`alice ar list`, `alice ex dump`, …) was used **exclusively as an
external reference oracle during development**: its output was compared against
this project's parser to confirm that the AFA archive reader was correct.

Specifically, it was used to:

- confirm archive entry counts and names across seven archives (59,267 entries);
- confirm v3 archive handling, which is encrypted and bit-unaligned and is the
  format the voice archives that matter actually use;
- establish where each archive's payload ends.

What it was **not** used for:

- it is not linked against, imported, or invoked at runtime;
- no alice-tools source code has been copied into this repository;
- no alice-tools source has been vendored into `external/`;
- it is not required to build, run, or use AliceSoundFetcher.

Verification against an external tool's observable output is the same kind of
activity as reading its documentation or the file format's specification: it
helps establish what the correct answer is. It does not make this project's own
code a derived work of alice-tools, because no alice-tools code is present in
this project.

**If that boundary is ever crossed** — for example if alice-tools source were
copied into `external/`, vendored, or the tool were invoked as part of the build
or of normal operation — this project would become a combined work and would need
to be relicensed under GPL-2.0 to remain distributable. Please raise this before
making such a change rather than after.

alice-tools itself carries third-party dependencies of its own (zlib, libpng,
libturbojpeg, libwebp, brotli, bzip2) under `licenses/` in its distribution.

## Windows SDK Debuggers (cdb) — Microsoft

The Windows SDK debugger (`cdb.exe`, part of the Windows SDK / Windows
Debugging Tools) was used to diagnose access violations in the game process:
obtaining the faulting address, disassembling call sites, and dumping the
patched vtable at the moment of the crash.

This is diagnostic tooling only. No Windows SDK code is included in, linked by,
or redistributed with this project. Use of the Windows SDK and Windows itself is
governed by the Microsoft licence and EULA applicable to your installation.

## Microsoft Visual C++ — Microsoft

Both projects are built with MSVC (Visual Studio, v14.5x toolset) targeting
Win32/x86, because AliceSoft System-4 games are 32-bit. The Microsoft Visual
C++ Redistributable may be redistributed under Microsoft's licence; this project
does not bundle it.

## DEFLATE / zlib — format specification only

`parser/Inflate.h` is an **independent, clean-room implementation** of the DEFLATE
decompression format written for this project from the published specifications:

- RFC 1951 — DEFLATE Compressed Data Format Specification version 1.3
- RFC 1950 — zlib Compressed Data Format Specification version 1.2

No zlib source code was copied, adapted, or linked. The implementation was
differentially tested against Node.js' `zlib` over 96 cases (byte-exact on all of
them) rather than derived from it.

The reason for writing it at all is worth recording: the obvious approach was to
call `RtlDecompressBuffer` from `ntdll` and avoid shipping a decompressor, but
`COMPRESSION_FORMAT_ZLIB` raises an access violation on these inputs, and
`COMPRESSION_FORMAT_DEFAULT` is LZNT1 rather than DEFLATE. Neither is usable.

---

## Test material

**No game assets, archives, executable code, or other content from any AliceSoft
game are contained in, redistributed by, or required by this repository.** The
tool operates only on files the user already owns and already has installed.

This project is not affiliated with, endorsed by, or connected to AliceSoft /
アリスソフト or any of its subsidiaries. All trademarks, game titles, and assets
belong to their respective owners. See also the disclaimer in
[`README.md`](README.md).

### libVorbis / Opus

The game binaries statically link libVorbis 1.3.3; the string `OpusHead` was
observed in the data section of `Evenicle.exe`. Neither library's code is present
in, linked by, or redistributed with this project — this is noted only because
that observation informed the archive-format investigation.