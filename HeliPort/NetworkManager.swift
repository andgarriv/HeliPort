//
//  NetworkManager.swift
//  HeliPort
//
//  Created by OpenIntelWireless on 2020/3/23.
//  Copyright (c) 2020 OpenIntelWireless. All rights reserved.
//

/*
 * This program and the accompanying materials are licensed and made available
 * under the terms and conditions of the The 3-Clause BSD License
 * which accompanies this distribution. The full text of the license may be found at
 * https://opensource.org/licenses/BSD-3-Clause
 */

import Cocoa
import SystemConfiguration

final class NetworkManager {
    static let supportedSecurityMode = [
        ITL80211_SECURITY_NONE,
        ITL80211_SECURITY_WEP,
        ITL80211_SECURITY_WPA_PERSONAL,
        ITL80211_SECURITY_WPA_PERSONAL_MIXED,
        ITL80211_SECURITY_WPA2_PERSONAL,
        ITL80211_SECURITY_PERSONAL,
        ITL80211_SECURITY_WPA_ENTERPRISE,
        ITL80211_SECURITY_WPA_ENTERPRISE_MIXED,
        ITL80211_SECURITY_WPA2_ENTERPRISE,
        ITL80211_SECURITY_ENTERPRISE,
        ITL80211_SECURITY_WPA3_ENTERPRISE
    ]

    static func connect(networkInfo: NetworkInfo, saveNetwork: Bool = false,
                        _ callback: ((_ result: Bool) -> Void)? = nil) {

        guard supportedSecurityMode.contains(networkInfo.auth.security) else {
            let alert = Alert(text: NSLocalizedString("Network security not supported: ")
                              + networkInfo.auth.security.description)
            alert.show()
            return
        }

        let getAuthInfoCallback: (_ auth: NetworkAuth, _ savePassword: Bool) -> Void = { auth, savePassword in
            DispatchQueue.global(qos: .background).async {
                StatusBarIcon.shared().connecting()
                let result: Bool
                if NetworkManager.requiresUsername(for: networkInfo.auth.security) {
                    result = NetworkManager.connectEnterpriseNetwork(networkInfo: networkInfo, auth: auth)
                } else {
                    result = connect_network_with_auth(networkInfo.ssid,
                                                       UInt32(networkInfo.auth.security.rawValue),
                                                       auth.username,
                                                       auth.password)
                }
                DispatchQueue.main.async {
                    if result {
                        if savePassword {
                            CredentialsManager.instance.save(networkInfo)
                        }
                    } else {
                        Log.error("Failed to connect to: \(networkInfo.ssid)")
                    }
                    callback?(result)
                }
            }
        }

        // Getting keychain access blocks UI Thread and makes everything freeze unless made async
        DispatchQueue.global().async {
            if let savedNetworkAuth = CredentialsManager.instance.get(networkInfo) {
                networkInfo.auth = savedNetworkAuth
                Log.debug("Connecting to network \(networkInfo.ssid) with saved password")
                CredentialsManager.instance.setAutoJoin(networkInfo.ssid, true)
                getAuthInfoCallback(networkInfo.auth, false)
                return
            }

            let requiresPassword = networkInfo.auth.password.isEmpty
            let requiresEnterpriseUsername = requiresUsername(for: networkInfo.auth.security) &&
                networkInfo.auth.username.isEmpty

            guard networkInfo.auth.security != ITL80211_SECURITY_NONE,
                  requiresPassword || requiresEnterpriseUsername else {
                getAuthInfoCallback(networkInfo.auth, saveNetwork)
                return
            }

            DispatchQueue.main.async {
                WiFiConfigWindow(windowState: .connectWiFi,
                                 networkInfo: networkInfo,
                                 getAuthInfoCallback: getAuthInfoCallback).show()
            }
        }
    }

    static func scanNetwork(sortBy areInIncreasingOrder: @escaping (NetworkInfo, NetworkInfo) -> Bool
                                = { $0.ssid < $1.ssid },
                            callback: @escaping (_ sortedNetworkInfoList: [NetworkInfo]) -> Void) {
        scanNetwork { result in
            callback(result.sorted(by: areInIncreasingOrder))
        }
    }

    static func scanNetwork(sortBy areInIncreasingOrder: @escaping (NetworkInfo, NetworkInfo) -> Bool
                                = { $0.ssid < $1.ssid },
                            callback: @escaping (_ knownNetworks: [NetworkInfo],
                                                 _ otherNetworks: [NetworkInfo]) -> Void) {
        DispatchQueue.global(qos: .background).async {
            let savedSSIDs = CredentialsManager.instance.getSavedNetworkSSIDs()
            scanNetwork { result in
                let known = result.filter { savedSSIDs.contains($0.ssid) }
                let other = result.subtracting(known)

                DispatchQueue.main.async {
                    callback(known.sorted(by: areInIncreasingOrder),
                             other.sorted(by: areInIncreasingOrder))
                }
            }
        }
    }

    private static func scanNetwork(callback: @escaping (_ networkInfoList: Set<NetworkInfo>) -> Void) {
        DispatchQueue.global(qos: .background).async {
            var list = network_info_list_t()
            get_network_list(&list)

            var result = Set<NetworkInfo>()
            let networks = Mirror(reflecting: list.networks).children.map({ $0.value }).prefix(Int(list.count))

            for element in networks {
                guard let network = element as? ioctl_network_info else {
                    continue
                }
                let ssid = String(ssid: network.ssid)
                guard !ssid.isEmpty else {
                    continue
                }

                let networkInfo = NetworkInfo(
                    ssid: ssid,
                    rssi: Int(network.rssi)
                )
                networkInfo.auth.security = getSecurityType(network)
                result.insert(networkInfo)
            }

            DispatchQueue.main.async {
                callback(result)
            }
        }
    }

    static func scanSavedNetworks() {
        DispatchQueue.global(qos: .background).async {
            let savedNetworks: [NetworkInfo] = CredentialsManager.instance.getSavedNetworks()
            guard savedNetworks.count > 0 else {
                Log.debug("No network saved for auto join")
                return
            }
            let scanTimer: Timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { timer in
                NetworkManager.scanNetwork { networkList in
                    let targetNetworks = savedNetworks.filter { networkList.contains($0) }
                    if targetNetworks.count > 0 {
                        // This will stop the timer completely
                        timer.invalidate()
                        Log.debug("Auto join timer stopped")
                        connectSavedNetworks(networks: targetNetworks)
                    }
                }
            }
            // Start executing code inside the timer immediately
            scanTimer.fire()
            let currentRunLoop = RunLoop.current
            currentRunLoop.add(scanTimer, forMode: .common)
            currentRunLoop.run()
        }
    }

    private static func connectSavedNetworks(networks: [NetworkInfo]) {
        DispatchQueue.global(qos: .background).async {
            let dispatchSemaphore = DispatchSemaphore(value: 0)
            var connected = false
            for network in networks where !connected {
                connect(networkInfo: network) { (result: Bool) in
                    connected = result
                    dispatchSemaphore.signal()
                }
                dispatchSemaphore.wait()
            }
        }
    }

    // Credit: vadian
    // https://stackoverflow.com/a/31838376/13164334
    static func getMACAddressFromBSD(bsd: String) -> String? {
        let MAC_ADDRESS_LENGTH = 6
        let separator = ":"

        var length: size_t = 0
        var buffer: [CChar]

        let bsdIndex = Int32(if_nametoindex(bsd))
        if bsdIndex == 0 {
            Log.error("Could not find index for bsd name \(bsd)")
            return nil
        }
        let bsdData = Data(bsd.utf8)
        var managementInfoBase = [CTL_NET,
                                  AF_ROUTE,
                                  0,
                                  AF_LINK,
                                  NET_RT_IFLIST,
                                  bsdIndex]

        if sysctl(&managementInfoBase, 6, nil, &length, nil, 0) < 0 {
            Log.error("Could not determine length of info data structure")
            return nil
        }

        buffer = [CChar](unsafeUninitializedCapacity: length, initializingWith: {buffer, initializedCount in
            for idx in 0..<length { buffer[idx] = 0 }
            initializedCount = length
        })

        if sysctl(&managementInfoBase, 6, &buffer, &length, nil, 0) < 0 {
            Log.error("Could not read info data structure")
            return nil
        }

        let infoData = Data(bytes: buffer, count: length)
        let indexAfterMsghdr = MemoryLayout<if_msghdr>.stride + 1
        let rangeOfToken = infoData[indexAfterMsghdr...].range(of: bsdData)!
        let lower = rangeOfToken.upperBound
        let upper = lower + MAC_ADDRESS_LENGTH
        let macAddressData = infoData[lower..<upper]
        let addressBytes = macAddressData.map { String(format: "%02x", $0) }
        return addressBytes.joined(separator: separator)
    }

    static func isReachable() -> Bool {
        guard let reachability = SCNetworkReachabilityCreateWithName(nil, "captive.apple.com") else {
            return false
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)

        var flags = SCNetworkReachabilityFlags()
        SCNetworkReachabilityGetFlags(reachability, &flags)

        let isReachable: Bool = flags.contains(.reachable)
        let needsConnection = flags.contains(.connectionRequired)
        let canConnectAutomatically = flags.contains(.connectionOnDemand) || flags.contains(.connectionOnTraffic)
        let canConnectWithoutUserInteraction = canConnectAutomatically && !flags.contains(.interventionRequired)
        return isReachable && (!needsConnection || canConnectWithoutUserInteraction)
    }

    static func getRouterAddress(bsd: String) -> String? {
        return getRouterAddressFromSysctl(bsd) ?? getRouterAddressFromNetstat(bsd)
    }

    // from https://stackoverflow.com/questions/30748480/swift-get-devices-wifi-ip-address/30754194#30754194
    static func getLocalAddress(bsd: String) -> String? {
        // Get list of all interfaces on the local machine:
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return nil
        }

        var ipV4: String?
        var ipV6: String?

        // For each interface ...
        for ifptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ifptr.pointee

            // Check for IPv4 or IPv6 interface:
            let addrFamily = interface.ifa_addr.pointee.sa_family
            guard addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) else {
                continue
            }

            // Check interface name:
            let name = String(cString: interface.ifa_name)
            guard name == bsd else {
                continue
            }

            // Convert interface address to a human readable string:
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                        &hostname, socklen_t(hostname.count),
                        nil, socklen_t(0), NI_NUMERICHOST)

            if addrFamily == UInt8(AF_INET) {
                ipV4 = String(cString: hostname)
            } else if addrFamily == UInt8(AF_INET6) {
                ipV6 = String(cString: hostname)
            }
        }

        freeifaddrs(ifaddr)

        // ipV4 has priority
        return ipV4 ?? ipV6
    }

    static func getSecurityType(_ info: ioctl_network_info) -> itl80211_security {
        let hasRSN = info.supported_rsnprotos & ITL80211_PROTO_RSN.rawValue != 0
        let hasWPA = info.supported_rsnprotos & ITL80211_PROTO_WPA.rawValue != 0

        let has8021X = info.rsn_akms & ITL80211_AKM_8021X.rawValue != 0
        let hasSHA256_8021X = info.rsn_akms & ITL80211_AKM_SHA256_8021X.rawValue != 0
        let hasPSK = info.rsn_akms & ITL80211_AKM_PSK.rawValue != 0
        let hasSHA256_PSK = info.rsn_akms & ITL80211_AKM_SHA256_PSK.rawValue != 0

        if hasRSN {
            if has8021X || hasSHA256_8021X {
                if has8021X && hasSHA256_8021X {
                    return ITL80211_SECURITY_ENTERPRISE
                }
                if has8021X {
                    return hasWPA ? ITL80211_SECURITY_WPA_ENTERPRISE_MIXED : ITL80211_SECURITY_WPA2_ENTERPRISE
                }
                return ITL80211_SECURITY_WPA3_ENTERPRISE
            }

            if hasPSK || hasSHA256_PSK {
                if hasPSK && hasSHA256_PSK {
                    return ITL80211_SECURITY_PERSONAL
                }
                if hasPSK {
                    return hasWPA ? ITL80211_SECURITY_WPA_PERSONAL_MIXED : ITL80211_SECURITY_WPA2_PERSONAL
                }
                return ITL80211_SECURITY_PERSONAL
            }
        } else if hasWPA {
            if has8021X || hasSHA256_8021X {
                return ITL80211_SECURITY_WPA_ENTERPRISE
            }
            if hasPSK || hasSHA256_PSK {
                return ITL80211_SECURITY_WPA_PERSONAL
            }
        } else if info.supported_rsnprotos == 0 {
            return ITL80211_SECURITY_NONE
        }
        return ITL80211_SECURITY_UNKNOWN
    }

    private static func requiresUsername(for security: itl80211_security) -> Bool {
        switch security {
        case ITL80211_SECURITY_WPA_ENTERPRISE,
             ITL80211_SECURITY_WPA_ENTERPRISE_MIXED,
             ITL80211_SECURITY_WPA2_ENTERPRISE,
             ITL80211_SECURITY_ENTERPRISE,
             ITL80211_SECURITY_WPA3_ENTERPRISE:
            return true
        default:
            return false
        }
    }
    private static func connectEnterpriseNetwork(networkInfo: NetworkInfo, auth: NetworkAuth) -> Bool {
        if auth.username.isEmpty || auth.password.isEmpty {
            Log.error("Enterprise credentials missing for \(networkInfo.ssid)")
            return false
        }

        // If a PMK is already available (hex), use IOCTL KEYAVAIL/KEYRUN path.
        if isHexPMK(auth.password) {
            return connect_network_with_auth(networkInfo.ssid,
                                             UInt32(networkInfo.auth.security.rawValue),
                                             auth.username,
                                             auth.password)
        }

        return runSupplicantTTLS(networkInfo: networkInfo, auth: auth)
    }

    private static func runSupplicantTTLS(networkInfo: NetworkInfo, auth: NetworkAuth) -> Bool {
        guard let interfaceName = currentInterfaceName() else {
            Log.error("Cannot determine interface name for enterprise supplicant")
            return false
        }

        guard let supplicantPath = firstExecutablePath([
            "/opt/homebrew/sbin/wpa_supplicant",
            "/usr/local/sbin/wpa_supplicant",
            "/usr/sbin/wpa_supplicant"
        ]) else {
            Log.error("wpa_supplicant not found. Install wpa_supplicant to use EAP-TTLS.")
            return false
        }

        let cliPath = firstExecutablePath([
            "/opt/homebrew/bin/wpa_cli",
            "/usr/local/bin/wpa_cli",
            "/usr/sbin/wpa_cli"
        ])

        let pidFile = "/var/run/heliport-\(interfaceName)-supplicant.pid"
        let configPath = "\(NSTemporaryDirectory())heliport-\(UUID().uuidString).conf"

        do {
            try buildTTLSConfig(networkInfo: networkInfo, auth: auth).write(
                toFile: configPath,
                atomically: true,
                encoding: .utf8
            )
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath)
        } catch {
            Log.error("Failed to write supplicant config: \(error.localizedDescription)")
            return false
        }

        defer {
            try? FileManager.default.removeItem(atPath: configPath)
        }

        let startCommand = """
        if [ -f \(shellQuote(pidFile)) ]; then
            oldpid=$(cat \(shellQuote(pidFile)) 2>/dev/null || true)
            if [ -n "$oldpid" ]; then
                kill "$oldpid" >/dev/null 2>&1 || true
            fi
        fi
        \(shellQuote(supplicantPath)) -B -D bsd -i \(shellQuote(interfaceName)) -c \(shellQuote(configPath)) -P \(shellQuote(pidFile))
        """
        let startResult = executePrivilegedShell(startCommand)
        if startResult.1 != 0 {
            Log.error("Failed to start wpa_supplicant for \(networkInfo.ssid)")
            return false
        }

        let connected: Bool
        if let cliPath = cliPath {
            connected = waitForSupplicantCompletion(
                cliPath: cliPath,
                interfaceName: interfaceName,
                expectedSSID: networkInfo.ssid,
                timeoutSeconds: 30
            )
        } else {
            // Fallback if wpa_cli is unavailable.
            connected = waitForRunState(ssid: networkInfo.ssid, timeoutSeconds: 30)
        }

        if !connected {
            let stopCommand = """
            if [ -f \(shellQuote(pidFile)) ]; then
                oldpid=$(cat \(shellQuote(pidFile)) 2>/dev/null || true)
                if [ -n "$oldpid" ]; then
                    kill "$oldpid" >/dev/null 2>&1 || true
                fi
                rm -f \(shellQuote(pidFile))
            fi
            """
            _ = executePrivilegedShell(stopCommand)
            Log.error("Enterprise TTLS authentication failed for \(networkInfo.ssid)")
        }

        return connected
    }

    private static func buildTTLSConfig(networkInfo: NetworkInfo, auth: NetworkAuth) -> String {
        let ssid = wpaQuote(networkInfo.ssid)
        let username = wpaQuote(auth.username)
        let password = wpaQuote(auth.password)
        let pmf = networkInfo.auth.security == ITL80211_SECURITY_WPA3_ENTERPRISE ? 2 : 1

        return """
        ctrl_interface=/var/run/wpa_supplicant
        ap_scan=1
        fast_reauth=1
        network={
            ssid="\(ssid)"
            key_mgmt=WPA-EAP WPA-EAP-SHA256
            proto=RSN
            pairwise=CCMP
            group=CCMP
            eap=TTLS
            identity="\(username)"
            password="\(password)"
            phase2="auth=MSCHAPV2"
            ieee80211w=\(pmf)
            priority=5
        }
        """
    }

    private static func waitForSupplicantCompletion(cliPath: String,
                                                    interfaceName: String,
                                                    expectedSSID: String,
                                                    timeoutSeconds: Int) -> Bool {
        let waitCommand = """
        i=0
        while [ "$i" -lt \(timeoutSeconds) ]; do
            status=$(\(shellQuote(cliPath)) -p /var/run/wpa_supplicant -i \(shellQuote(interfaceName)) status 2>/dev/null || true)
            state=$(printf "%s\\n" "$status" | /usr/bin/awk -F= '/^wpa_state=/{print $2}')
            current=$(printf "%s\\n" "$status" | /usr/bin/awk -F= '/^ssid=/{print $2}')

            if [ "$state" = "COMPLETED" ] && [ "$current" = \(shellQuote(expectedSSID)) ]; then
                exit 0
            fi

            i=$((i + 1))
            sleep 1
        done
        exit 1
        """

        return executePrivilegedShell(waitCommand).1 == 0
    }

    private static func waitForRunState(ssid: String, timeoutSeconds: Int) -> Bool {
        for _ in 0..<timeoutSeconds {
            var state: UInt32 = 0
            if get_80211_state(&state), state == ITL80211_S_RUN {
                var staInfo = station_info_t()
                if get_station_info(&staInfo) == KERN_SUCCESS {
                    if String(ssid: staInfo.ssid) == ssid {
                        return true
                    }
                }
            }
            Thread.sleep(forTimeInterval: 1)
        }

        return false
    }

    private static func currentInterfaceName() -> String? {
        var platformInfo = platform_info_t()
        guard get_platform_info(&platformInfo) else {
            return nil
        }
        let name = String(cCharArray: platformInfo.device_info_str)
        return name.isEmpty ? nil : name
    }

    private static func executePrivilegedShell(_ command: String) -> (String?, Int32) {
        let escaped = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let scriptSource = "do shell script \"\(escaped)\" with administrator privileges"

        var errorInfo: NSDictionary?
        let script = NSAppleScript(source: scriptSource)
        let descriptor = script?.executeAndReturnError(&errorInfo)

        if let errorInfo {
            let code = (errorInfo[NSAppleScript.errorNumber] as? Int32) ?? 1
            let message = (errorInfo[NSAppleScript.errorMessage] as? String) ?? "Unknown script failure"
            Log.error("Privileged command failed (\(code)): \(message)")
            return (nil, code)
        }

        let output = descriptor?.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines)
        return (output?.isEmpty == true ? nil : output, 0)
    }

    private static func shellQuote(_ value: String) -> String {
        return "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func wpaQuote(_ value: String) -> String {
        return value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private static func firstExecutablePath(_ candidates: [String]) -> String? {
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    private static func isHexPMK(_ value: String) -> Bool {
        let candidate: String
        if value.lowercased().hasPrefix("pmk:") {
            candidate = String(value.dropFirst(4))
        } else {
            candidate = value
        }

        if candidate.count != 64 {
            return false
        }
        return candidate.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil
    }

    private static func getRouterAddressFromNetstat(_ bsd: String) -> String? {
        var ipAddr: String?

        autoreleasepool {
            // from Goshin
            let ipAddressRegex = #"\s([a-fA-F0-9\.:]+)(\s|%)"# // for ipv4 and ipv6

            let routerCommand = ["-c", "netstat -rn", "|", "egrep -o", "default.*\(bsd)"]
            guard let routerOutput = Commands.execute(executablePath: .shell, args: routerCommand).0 else { return }
            let regex = try? NSRegularExpression.init(pattern: ipAddressRegex, options: [])
            let firstMatch = regex?.firstMatch(in: routerOutput,
                                               options: [],
                                               range: NSRange(location: 0, length: routerOutput.count))
            if let range = firstMatch?.range(at: 1) {
                if let swiftRange = Range(range, in: routerOutput) {
                    ipAddr = String(routerOutput[swiftRange])
                }
            } else {
                Log.debug("Could not find router ip address")
            }
        }

        return ipAddr
    }

    // Modified from https://stackoverflow.com/a/67780630 to support ipv6 and bsd filtering
    // See https://opensource.apple.com/source/network_cmds/network_cmds-606.40.2/netstat.tproj/route.c
    private static func getRouterAddressFromSysctl(_ bsd: String) -> String? {
        var mib: [Int32] = [CTL_NET,
                            PF_ROUTE,
                            0,
                            0,
                            NET_RT_DUMP2,
                            0]
        let mibSize = u_int(mib.count)

        var bufSize = 0
        sysctl(&mib, mibSize, nil, &bufSize, nil, 0)

        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { buf.deallocate() }
        buf.initialize(repeating: 0, count: bufSize)

        guard sysctl(&mib, mibSize, buf, &bufSize, nil, 0) == 0 else { return nil }

        // Routes
        var next = buf
        let lim = next.advanced(by: bufSize)
        while next < lim {
            let rtm = next.withMemoryRebound(to: rt_msghdr2.self, capacity: 1) { $0.pointee }
            var ifname = [CChar](repeating: 0, count: Int(IFNAMSIZ + 1))
            if_indextoname(UInt32(rtm.rtm_index), &ifname)

            if String(cString: ifname) == bsd, let addr = getRouterAddressFromRTM(rtm, next) {
                return addr
            }

            next = next.advanced(by: Int(rtm.rtm_msglen))
        }

        return nil
    }

    private static func getRouterAddressFromRTM(_ rtm: rt_msghdr2,
                                                _ ptr: UnsafeMutablePointer<UInt8>) -> String? {
        var rawAddr = ptr.advanced(by: MemoryLayout<rt_msghdr2>.stride)

        for idx in 0..<RTAX_MAX {
            let sockAddr = rawAddr.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0.pointee }

            if (rtm.rtm_addrs & (1 << idx)) != 0 && idx == RTAX_GATEWAY {
                switch Int32(sockAddr.sa_family) {
                case AF_INET:
                    let sAddr = rawAddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }.sin_addr
                    // Take the first match, assuming its destination is "default"
                    return String(cString: inet_ntoa(sAddr), encoding: .ascii)
                case AF_INET6: // Not tested, maybe a garbage address from ipv4 will come first?
                    var sAddr6 = rawAddr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }.sin6_addr
                    var addrV6 = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    inet_ntop(AF_INET6, &sAddr6, &addrV6, socklen_t(INET6_ADDRSTRLEN))
                    return String(cString: addrV6, encoding: .ascii)
                default: break
                }
            }

            rawAddr = rawAddr.advanced(by: Int(sockAddr.sa_len))
        }

        return nil
    }
}
