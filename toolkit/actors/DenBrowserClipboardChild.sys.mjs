/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export class DenBrowserClipboardChild extends JSWindowActorChild {
  handleEvent(event) {
    if (!event.isTrusted || event.type != "DenBrowserCopyBlocked") {
      return;
    }

    this.sendAsyncMessage("DenBrowserClipboard:Blocked", {
      sourceBrowsingContextId: this.browsingContext.id,
      openerBrowsingContextId: this.browsingContext.top.opener?.id ?? null,
    });
  }
}
