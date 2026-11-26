import AppKit
import SwiftUI
import WebKit

struct ControlBotWebView: NSViewRepresentable {
    let url: URL
    let reloadToken: UUID

    func makeCoordinator() -> Coordinator {
        Coordinator(initialURL: url, initialReloadToken: reloadToken)
    }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        context.coordinator.allowedHost = (url.host ?? "").lowercased()
        if context.coordinator.lastURL != url {
            context.coordinator.lastURL = url
            context.coordinator.lastReloadToken = reloadToken
            webView.load(URLRequest(url: url))
            return
        }
        if context.coordinator.lastReloadToken != reloadToken {
            context.coordinator.lastReloadToken = reloadToken
            if webView.url != nil {
                webView.reload()
            } else {
                webView.load(URLRequest(url: url))
            }
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        var lastURL: URL
        var lastReloadToken: UUID
        var allowedHost: String

        init(initialURL: URL, initialReloadToken: UUID) {
            self.lastURL = initialURL
            self.lastReloadToken = initialReloadToken
            self.allowedHost = (initialURL.host ?? "").lowercased()
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let targetURL = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            let host = (targetURL.host ?? "").lowercased()
            let scheme = (targetURL.scheme ?? "").lowercased()
            if scheme == "about"
                || host == allowedHost
                || host == "127.0.0.1"
                || host == "localhost"
                || host == "::1" {
                decisionHandler(.allow)
                return
            }
            NSWorkspace.shared.open(targetURL)
            decisionHandler(.cancel)
        }

        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for navigationAction: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            if let targetURL = navigationAction.request.url {
                NSWorkspace.shared.open(targetURL)
            }
            return nil
        }
    }
}
