# Third-party notices

SopsHQ includes third-party code in two places:

- **Web libraries** under `internal/web/static/vendor/`, minified, embedded in the
  binary and served by the admin panel. Each is MIT-licensed.
- **One Go module,** `rsc.io/qr`, compiled into the binary for the TOTP enrollment QR
  code. It is BSD-3-Clause licensed.

## Contents

- [Web libraries](#web-libraries)
- [MIT licence text](#mit-licence-text)
- [rsc.io/qr](#rscioqr)

## Web libraries

| Library | Version | Files | Licence | Copyright |
|---|---|---|---|---|
| Bootstrap | 5.3.8 | `bootstrap.min.css`, `bootstrap.bundle.min.js` | MIT | 2011-2025 The Bootstrap Authors |
| Popper | as bundled by Bootstrap 5.3.8 | inside `bootstrap.bundle.min.js` | MIT | 2019 Federico Zivolo |
| jQuery | 3.7.1 | `jquery.min.js` | MIT | OpenJS Foundation and other contributors |
| DataTables | 2.0.8 | `datatables.min.js` | MIT | SpryMedia Ltd |
| DataTables Bootstrap 5 integration | as DataTables | `dataTables.bootstrap5.min.js`, `dataTables.bootstrap5.min.css` | MIT | SpryMedia Ltd |
| Select2 | 4.1.0-rc.0 | `select2.min.js`, `select2.min.css` | MIT | 2012-2017 Kevin Brown, Igor Vaynberg, and Select2 contributors |

How each fact was established:

- Bootstrap: version, copyright and "Licensed under MIT" are in the banner of the
  vendored files themselves.
- Popper: `bootstrap.bundle.min.js` is Bootstrap's bundle build, which compiles Popper
  in (its code is in the file) but carries no Popper banner. The licence and copyright
  shown are those of Popper's own published `LICENSE.md`; they are not in the vendored
  file.
- jQuery: the banner names the version and the OpenJS Foundation, and points at
  `jquery.org/license`, which states the MIT licence.
- DataTables: the banner names version 2.0.8 and SpryMedia Ltd, and points at
  `datatables.net/license`, which states that DataTables 1.10 and newer is MIT. The
  Bootstrap 5 integration files carry the same banner owner and no version of their own.
- Select2: the banner names version 4.1.0-rc.0 and points at the library's
  `LICENSE.md`, which is the MIT licence with the copyright shown above.
- `select2.min.css` and `dataTables.bootstrap5.min.css` carry no banner. They are
  attributed to the library whose script sits beside them.

## MIT licence text

The MIT licence text, as each project publishes it, applies to the copyright holders
named above:

```
Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## rsc.io/qr

`rsc.io/qr` v0.2.0 (see `go.mod`) is compiled into the binary. Its licence, copied from
the module's `LICENSE` file:

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
