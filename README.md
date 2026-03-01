# mime

MIME type detection and mapping by extension plus sniffing helpers.

`mime` provides deterministic utilities for working with content types in modern C++:

- Extension -> MIME mapping (case-insensitive)
- Filesystem path detection
- Lightweight content sniffing (magic bytes)
- Deterministic fallback behavior

Header-only. Zero external dependencies.

## Download

https://vixcpp.com/registry/pkg/gaspardkirira/mime

## Why mime?

Serving files or handling uploads often leads to:

- Case-sensitive extension bugs
- Incorrect default content types
- Inconsistent fallback behavior
- Trusting extensions blindly
- Missing detection for binary formats

This library provides:

- Case-insensitive extension lookup
- Clean default MIME mapping table
- Optional byte-level sniffing for common formats
- Safe fallback to `application/octet-stream`
- Deterministic behavior across platforms

No HTTP framework.
No filesystem abstraction.
No hidden global state.

Just explicit MIME primitives.

## Installation

### Using Vix Registry

```bash
vix add gaspardkirira/mime
vix deps
```

### Manual

```bash
git clone https://github.com/GaspardKirira/mime.git
```

Add the `include/` directory to your project.

## Dependency

Requires C++17 or newer.

No external dependencies.

## Quick Examples

### From Extension

```cpp
#include <mime/mime.hpp>
#include <iostream>

int main()
{
    std::cout << mime::from_extension(".png") << "\n";  // image/png
    std::cout << mime::from_extension("HTML") << "\n";  // text/html; charset=utf-8
}
```

### From Filesystem Path

```cpp
#include <mime/mime.hpp>
#include <filesystem>
#include <iostream>

int main()
{
    std::filesystem::path p = "assets/app.js";
    std::cout << mime::from_path(p) << "\n";
}
```

### Sniff Magic Bytes

```cpp
#include <mime/mime.hpp>
#include <vector>
#include <cstdint>
#include <iostream>

int main()
{
    std::vector<std::uint8_t> png = {
        0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A
    };

    std::cout << mime::sniff(png) << "\n"; // image/png
}
```

### Combined Detection

```cpp
#include <mime/mime.hpp>
#include <vector>
#include <cstdint>
#include <iostream>

int main()
{
    std::vector<std::uint8_t> pdf = {
        0x25,0x50,0x44,0x46,0x2D
    };

    std::cout << mime::detect(".unknown", pdf) << "\n"; // application/pdf
}
```

## API Overview

```cpp
// Extension mapping
mime::from_extension(ext, fallback);

// Path mapping
mime::from_path(path, fallback);

// Byte sniffing
mime::sniff(bytes, fallback);

// Combined detection
mime::detect(ext, bytes, fallback);
```

## Supported Sniffed Formats

- PNG
- JPEG
- GIF
- PDF
- ZIP
- MP3 (ID3)
- MP4
- WebM (EBML)

Sniffing is intentionally conservative.

## Complexity

Let:

- N = number of bytes inspected (small header prefix)

| Operation         | Time Complexity |
|------------------|-----------------|
| Extension lookup | O(1)            |
| Path lookup      | O(1)            |
| Sniffing         | O(N)            |

N is typically very small (first 8 to 64 bytes).

## Semantics

- Extension lookup is case-insensitive.
- Unknown extensions return `application/octet-stream`.
- `detect()` prefers extension over sniffing.
- Sniffing checks strong format signatures only.
- No filesystem I/O is performed internally.

## Design Principles

- Deterministic behavior
- Minimal abstraction
- Explicit fallback semantics
- Standards-aware defaults
- Header-only simplicity

This library focuses strictly on MIME detection.

If you need:

- Full HTTP response handling
- Content negotiation
- Media type parsing
- Advanced MIME database management

Build them on top of this layer.

## Tests

```bash
vix build
vix test
```

Tests verify:

- Extension mapping correctness
- Case-insensitive handling
- Sniff detection accuracy
- Fallback behavior
- Combined detection semantics

## License

MIT License\
Copyright (c) Gaspard Kirira

