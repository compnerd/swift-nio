
#if os(Windows)

@_exported
import ucrt
import CNIOWindows

import let WinSDK.INADDR_ANY
import let WinSDK.INET_ADDRSTRLEN
import let WinSDK.INET6_ADDRSTRLEN

import struct WinSDK.ADDRESS_FAMILY
import struct WinSDK.IN_ADDR
import struct WinSDK.IN6_ADDR
import struct WinSDK.LINGER
import struct WinSDK.SOCKADDR_IN
import struct WinSDK.SOCKADDR_IN6
import struct WinSDK.SOCKADDR_STORAGE
import struct WinSDK.SOCKADDR_UN

internal typealias in_addr = WinSDK.IN_ADDR
internal typealias in6_addr = WinSDK.IN6_ADDR

internal typealias sa_family_t = WinSDK.ADDRESS_FAMILY

internal typealias sockaddr_in = WinSDK.SOCKADDR_IN
internal typealias sockaddr_in6 = WinSDK.SOCKADDR_IN6
internal typealias sockaddr_un = WinSDK.SOCKADDR_UN
internal typealias sockaddr_storage = WinSDK.SOCKADDR_STORAGE

internal typealias linger = WinSDK.LINGER

internal let INADDR_ANY = WinSDK.INADDR_ANY
internal let INET_ADDRSTRLEN = WinSDK.INET_ADDRSTRLEN
internal let INET6_ADDRSTRLEN = WinSDK.INET6_ADDRSTRLEN

internal typealias MMsgHdr = CNIOWindows_mmsghdr

#endif
