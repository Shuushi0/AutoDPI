# Third-party software

AutoDPI is licensed under the GNU General Public License v3.0 or later (see `LICENSE`).
The release archives contain the programs below; each part keeps its own license.

## What each program contains

| Program | Third-party parts |
|---|---|
| `autodpi` (macOS), `autodpi.exe` (Windows) | the Go standard library and runtime; golang.org/x/net, and on Windows golang.org/x/sys; embedded helpers: sing-box and byedpi's `ciadpi` (both below) |
| `autodpi-tray.exe` (Windows tray app) | the Go standard library and runtime; golang.org/x/sys; fyne.io/systray (which links github.com/godbus/dbus/v5); go-webview2 with go-winloader and Microsoft's WebView2Loader.dll |
| `AutoDPI.app` (macOS menu bar app) | none: Swift and the system frameworks only |

| Component | Version | License | Source |
|---|---|---|---|
| [Go](https://go.dev) standard library and runtime | 1.27.1 | BSD-3-Clause (text below) | the Go distribution |
| golang.org/x/net, golang.org/x/sys | v0.61.0, v0.49.0 | BSD-3-Clause (the Go text below) | `go.mod` |
| [sing-box](https://github.com/SagerNet/sing-box) | 1.14.4 | GPL-3.0-or-later, with the upstream clause that derivative works may not use its name | built from source by `scripts/build-singbox.sh` with `tools/singbox/` (pinned in `go.mod`/`go.sum`); its own dependencies are listed below |
| [byedpi](https://github.com/hufrea/byedpi) (`ciadpi`) | 0.17.3 | MIT (text below) | built from the upstream tag by `scripts/fetch-bins.sh`; the Windows build is the upstream release |
| [fyne.io/systray](https://github.com/fyne-io/systray) (Windows tray app only) | v1.12.2 | Apache-2.0 (text below) | `go.mod` |
| [godbus/dbus](https://github.com/godbus/dbus) (Windows tray app only, through systray) | v5.1.0 | BSD-2-Clause (text below) | `go.mod` |
| [go-webview2](https://github.com/jchv/go-webview2) (Windows tray app only) | v0.0.0-20260205173254-56598839c808 | MIT (text below) | `go.mod` |
| [go-winloader](https://github.com/jchv/go-winloader) (Windows tray app only) | v0.0.0-20250406163304-c1995be93bd1 | ISC (text below) | `go.mod` |
| Microsoft WebView2Loader.dll, embedded by go-webview2 (Windows tray app only) | as pinned by go-webview2 | BSD-3-Clause (text below) | the go-webview2 module, `webviewloader/sdk` |

Because sing-box is GPL, the combined binaries are distributed under the GPL: the complete corresponding
source is this repository plus the pinned upstream sources named here.

## Inside the sing-box binaries

sing-box is a Go program; the slim build links the modules below (versions as pinned in
`tools/singbox/go.sum`). Each module's license text is in its source at that version.

On Windows, sing-box.exe also carries **wintun.dll 0.14.1** (Wintun, Copyright © 2018-2021 WireGuard
LLC), embedded by sing-tun and extracted at run time to create the TUN adapter. The prebuilt Wintun DLL
is distributed under WireGuard LLC's prebuilt-binaries license (see https://www.wintun.net/), which
allows it to be shipped unmodified inside software that uses it.

| Module | Version | License |
|---|---|---|
| github.com/ajg/form | v1.5.1 | BSD-3-Clause |
| github.com/andybalholm/brotli | v1.1.0 | MIT |
| github.com/anytls/sing-anytls | v0.0.11 | GPL-3.0 |
| github.com/caddyserver/certmagic | v0.25.3-0.20260421143802-60d9d8b415d6 | Apache-2.0 |
| github.com/caddyserver/zerossl | v0.1.5 | MIT |
| github.com/clipperhouse/uax29/v2 | v2.2.0 | MIT |
| github.com/coder/websocket | v1.8.14 | ISC |
| github.com/cretz/bine | v0.2.0 | MIT |
| github.com/database64128/netx-go (macOS only) | v0.1.1 | BSD-3-Clause |
| github.com/database64128/tfo-go/v2 | v2.3.2 | MIT |
| github.com/fsnotify/fsnotify | v1.9.0 | BSD-3-Clause |
| github.com/go-chi/chi/v5 | v5.2.5 | MIT |
| github.com/go-chi/render | v1.0.3 | MIT |
| github.com/go-ole/go-ole (Windows only) | v1.3.0 | MIT |
| github.com/gobwas/httphead | v0.1.0 | MIT |
| github.com/gobwas/pool | v0.2.1 | MIT |
| github.com/gofrs/uuid/v5 | v5.5.1 | MIT |
| github.com/google/btree | v1.1.3 | Apache-2.0 |
| github.com/hashicorp/yamux | v0.1.2 | MPL-2.0 |
| github.com/inconshreveable/mousetrap (Windows only) | v1.1.0 | Apache-2.0 |
| github.com/klauspost/compress | v1.19.1 | Apache-2.0 |
| github.com/klauspost/cpuid/v2 | v2.3.0 | MIT |
| github.com/libdns/libdns | v1.1.1 | MIT |
| github.com/logrusorgru/aurora | v2.0.3+incompatible | Unlicense |
| github.com/mattn/go-runewidth | v0.0.27 | MIT |
| github.com/metacubex/utls | v1.8.7 | BSD-3-Clause |
| github.com/mholt/acmez/v3 | v3.1.6 | Apache-2.0 |
| github.com/miekg/dns | v1.1.72 | BSD-3-Clause |
| github.com/oschwald/maxminddb-golang | v1.13.1 | ISC |
| github.com/sagernet/bbolt | v0.0.0-20260915102804-500ee1e84832 | MIT |
| github.com/sagernet/cors | v1.2.1 | MIT |
| github.com/sagernet/fswatch | v0.1.2 | GPL-3.0 |
| github.com/sagernet/gvisor | v0.0.0-20260727.0-sing-box-mod.1 | Apache-2.0 |
| github.com/sagernet/sing | v0.9.7-0.20261023115459-5dc452e537bf | GPL-3.0 |
| github.com/sagernet/sing-mux | v0.3.10-0.20260929204512-caf09fe32475 | GPL-3.0 |
| github.com/sagernet/sing-shadowsocks | v0.2.9-0.20260929204512-65740e0f0e3e | GPL-3.0 |
| github.com/sagernet/sing-shadowsocks2 | v0.2.2-0.20260929152114-a69d1086332b | GPL-3.0 |
| github.com/sagernet/sing-shadowtls | v0.2.2-0.20260928201441-a9c0127d5c99 | GPL-3.0 |
| github.com/sagernet/sing-snell | v0.0.0-20260904135315-bc5a12ac736f | GPL-3.0 |
| github.com/sagernet/sing-tun | v0.9.7-0.20261023115432-040db71fcd33 | GPL-3.0 |
| github.com/sagernet/sing-vmess | v0.2.9-0.20261019223527-a0c58542bd9d | GPL-3.0 |
| github.com/sagernet/smux | v1.5.50-sing-box-mod.1 | MIT |
| github.com/sagernet/wireguard-go | v0.0.8-0.20261022215841-e4d85ef2ed38 | MIT |
| github.com/sagernet/ws | v0.0.0-20231204124109-acfe8907c854 | MIT |
| github.com/spf13/cobra | v1.10.2 | Apache-2.0 |
| github.com/spf13/pflag | v1.0.10 | BSD-3-Clause |
| github.com/vishvananda/netns | v0.0.5 | Apache-2.0 |
| github.com/zeebo/blake3 | v0.2.4 | CC0-1.0 |
| go.uber.org/multierr | v1.11.0 | MIT |
| go.uber.org/zap | v1.27.1 | MIT |
| go.uber.org/zap/exp | v0.3.0 | MIT |
| go4.org/netipx | v0.0.0-20231129151722-fdeea329fbba | BSD-3-Clause |
| golang.org/x/crypto | v0.54.0 | BSD-3-Clause |
| golang.org/x/exp | v0.0.0-20260410095643-746e56fc9e2f | BSD-3-Clause |
| golang.org/x/mod | v0.37.0 | BSD-3-Clause |
| golang.org/x/net | v0.57.0 | BSD-3-Clause |
| golang.org/x/sync | v0.22.0 | BSD-3-Clause |
| golang.org/x/sys | v0.47.0 | BSD-3-Clause |
| golang.org/x/term | v0.45.0 | BSD-3-Clause |
| golang.org/x/text | v0.40.0 | BSD-3-Clause |
| golang.org/x/time | v0.15.0 | BSD-3-Clause |
| golang.zx2c4.com/wintun (Windows only) | v0.0.0-20230126152724-0fa3db229ce2 | MIT |
| golang.zx2c4.com/wireguard/wgctrl | v0.0.0-20241231184526-a9ab2273dd10 | MIT |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20251202230838-ff82c1b0f217 | Apache-2.0 |
| google.golang.org/grpc | v1.79.1 | Apache-2.0 |
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause |
| lukechampine.com/blake3 | v1.3.0 | MIT |

## Go license (BSD-3-Clause)

Applies to the Go standard library and runtime in every Go program here, and to golang.org/x/net and
golang.org/x/sys.

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
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

## godbus/dbus license (BSD-2-Clause)

Copyright (c) 2013, Georg Reinke (<guelfey at gmail dot com>), Google
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## byedpi license (MIT)

MIT License

Copyright (c) 2024 hufrea

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## go-webview2 license (MIT)

MIT License

Copyright (c) 2020 John Chadwick
Some portions Copyright (c) 2017 Serge Zaitsev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## go-winloader license (ISC)

# ISC License

Copyright © 2021, John Chadwick <john@jchw.io>

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## WebView2Loader license (BSD-3-Clause, Microsoft)

Copyright (C) Microsoft Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * The name of Microsoft Corporation, or the names of its contributors 
may not be used to endorse or promote products derived from this
software without specific prior written permission.

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

## fyne.io/systray license (Apache-2.0)

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2014 Brave New Software Project, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
