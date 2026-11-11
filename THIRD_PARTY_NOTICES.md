# Third-party notices

uastack includes work from the OPC Foundation:

- The server is ported from [OPC UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard).
- `internal/gen/schema/` (Opc.Ua.NodeSet2.xml, Opc.Ua.Types.bsd, NodeIds.csv, AttributeIds.csv, StatusCode.csv)
  and `server/ns0/Opc.Ua.NodeSet2.xml.gz` come from the OPC Foundation, as does the code generated from them
  (`ua/types_gen.go`, `ua/status_gen.go`, `ua/id/ids_gen.go`).

These are licensed under the OPC Foundation MIT License 1.00:

```
OPC Foundation MIT License 1.00

Copyright (c) 2005-2025 OPC Foundation, Inc. Permission is hereby granted,
free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Source: https://opcfoundation.org/license/mit.html
