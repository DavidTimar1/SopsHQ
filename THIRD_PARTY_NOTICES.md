# Third-party notices

SopsHQ ships these web libraries, unmodified and minified, under
`internal/web/static/vendor/`. They are embedded in the binary and served by the admin
panel. Each is MIT-licensed. The Go module dependencies are listed in `go.mod`.

| Library | Version | Files | Licence | Copyright |
|---|---|---|---|---|
| Bootstrap | 5.3.8 | `bootstrap.min.css`, `bootstrap.bundle.min.js` | MIT | 2011-2025 The Bootstrap Authors |
| jQuery | 3.7.1 | `jquery.min.js` | MIT | OpenJS Foundation and other contributors |
| DataTables | 2.0.8 | `datatables.min.js` | MIT | SpryMedia Ltd |
| DataTables Bootstrap 5 integration | as DataTables | `dataTables.bootstrap5.min.js`, `dataTables.bootstrap5.min.css` | MIT | SpryMedia Ltd |
| Select2 | 4.1.0-rc.0 | `select2.min.js`, `select2.min.css` | MIT | 2012-2017 Kevin Brown, Igor Vaynberg, and Select2 contributors |

How each fact was established:

- Bootstrap: version, copyright and "Licensed under MIT" are in the banner of the
  vendored files themselves.
- jQuery: the banner names the version and the OpenJS Foundation, and points at
  `jquery.org/license`, which states the MIT licence.
- DataTables: the banner names version 2.0.8 and SpryMedia Ltd, and points at
  `datatables.net/license`, which states that DataTables 1.10 and newer is MIT. The
  Bootstrap 5 integration files carry the same banner owner and no version of their own.
- Select2: the banner names version 4.1.0-rc.0 and points at the library's
  `LICENSE.md`, which is the MIT licence with the copyright shown above.
- `select2.min.css` and `dataTables.bootstrap5.min.css` carry no banner. They are
  attributed to the library whose script sits beside them.

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
