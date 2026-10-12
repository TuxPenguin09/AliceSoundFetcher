# AliceSoundFetcher

## Disclaimer

This project is an independent educational and research tool.

It is not affiliated with, endorsed by, or connected to AliceSoft / アリスソフト, ChampionSoft, or any of their subsidiaries.

All trademarks, game titles, and assets belong to their respective owners.

This is an independent fan-made tool. It is not produced, endorsed, or
supported by AliceSoft / アリスソフト or ChampionSoft.

This tool is intended for:
- Educational study of game file formats
- Audio playback tracing and logging analysis
- Learning Windows process injection and runtime monitoring techniques

No game assets are redistributed by this project.

## Usage

Drag an AliceSoft System game executable onto `AliceSoundFetcher.exe`. It reads the
game's `.afa` archives, injects a tracking DLL, and writes confirmed archive entry
names to `AliceSoundFetcher.log`, which is mirrored live in a separate window that
stays open after the game exits.

```
AliceSoundFetcher.exe <game.exe>            # normal run
AliceSoundFetcher.exe <game.exe> --verbose  # also log every hooked call
AliceSoundFetcher.exe --tail <logfile>      # viewer window only
```

### Settings

Optional, read from `AliceSoundFetcher.ini` beside the executable. With no file at
all, the defaults apply. See [`AliceSoundFetcher.ini.example`](AliceSoundFetcher.ini.example).

| Setting | Default | Effect |
| --- | --- | --- |
| `verbose` | `0` | Log every hooked call, not just confirmed names |
| `dumpObjects` | `0` | Dump sound-object memory and scan it for entry names |
| `hookComparisons` | `0` | Hook the CRT `strcmp` family |
| `classes` | built-in list | Comma-separated classes to hook |

`--verbose` overrides the file for one run.

## Licence

Apache License 2.0 — see [`LICENSE.txt`](LICENSE.txt).

Third-party software used during development is credited in
[`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md), which also documents one
compatibility point that matters: `alice-tools` is GPL-2.0 and is used purely
as a verification oracle, never linked or vendored.