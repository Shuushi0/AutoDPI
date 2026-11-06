import SwiftUI
import AppKit

// Developer/test modes (see DevTools.swift) run headless and exit.
let cliArgs = Array(CommandLine.arguments.dropFirst())
if MainActor.assumeIsolated({ DevTools.run(cliArgs) }) { exit(0) }

// One menu bar item is enough.
if let bid = Bundle.main.bundleIdentifier {
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: bid)
        .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
    if !others.isEmpty { exit(0) }
}

// Stop cleanly on SIGTERM/SIGINT so the child `autodpi ui` goes away too.
signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
termSource.setEventHandler { NSApp.terminate(nil) }
termSource.resume()
let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
intSource.setEventHandler { NSApp.terminate(nil) }
intSource.resume()

MainActor.assumeIsolated { AppStore.shared.start() }
AutoDPIApp.main()
