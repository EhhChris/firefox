# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

## DenBrowser Brand

-brand-shorter-name = DenBrowser
-brand-short-name = DenBrowser
-brand-shortcut-name = DenBrowser
-brand-full-name = DenBrowser
# This brand name is used when the name must remain constant across versions.
-brand-product-name = DenBrowser
-vendor-short-name = DenBrowser
trademarkInfo = { " " }

## About dialog
# Shown in the About { -brand-short-name } dialog. The github-link label is
# overlaid onto the <label data-l10n-name="github-link"> element in
# aboutDialog.xhtml, which supplies the href.
about-denbrowser-description = { -brand-short-name } is a hardened web browser built on Mozilla Firefox and distributed under the same Mozilla Public License. View the source code and patches on <label data-l10n-name="github-link">GitHub</label>.

# Shown immediately to the right of the version in the About
# { -brand-short-name } dialog, e.g. "153.0esr (64-bit) (build a1b2c3d)".
# Variables:
#   $commit (String): abbreviated DenBrowser repository commit this build was
#     produced from, with a "-dirty" suffix when the tree carried uncommitted
#     changes at build time. Injected into aboutDialog.js by build.sh.
about-denbrowser-build = (build { $commit })
