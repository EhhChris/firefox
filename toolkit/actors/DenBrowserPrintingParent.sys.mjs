/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

export class DenBrowserPrintingParent extends JSWindowActorParent {
  receiveMessage(message) {
    if (message.name != "DenBrowserPrinting:Blocked") {
      return undefined;
    }

    let fallbackBrowser = this.browsingContext.top.embedderElement;
    let sourceContext = BrowsingContext.get(
      message.data.sourceBrowsingContextId
    );
    let openerContext = message.data.openerBrowsingContextId
      ? BrowsingContext.get(message.data.openerBrowsingContextId)
      : null;
    let sourceBrowser = sourceContext?.top?.embedderElement || fallbackBrowser;
    let openerBrowser =
      openerContext?.top?.embedderElement ||
      sourceContext?.top?.opener?.top?.embedderElement;
    if (!openerBrowser?.isConnected || !openerBrowser.documentGlobal) {
      openerBrowser = null;
    }
    let chromeRoot = sourceBrowser?.ownerDocument?.documentElement;
    let browser =
      openerBrowser &&
      (!sourceBrowser?.isConnected || chromeRoot?.hasAttribute("chromehidden"))
        ? openerBrowser
        : sourceBrowser;

    if (browser?.isConnected && browser.documentGlobal) {
      let chromeWindow = browser.documentGlobal;
      browser.dispatchEvent(
        new chromeWindow.CustomEvent("DenBrowserPrintingBlocked", {
          bubbles: true,
        })
      );
    }

    return undefined;
  }
}
