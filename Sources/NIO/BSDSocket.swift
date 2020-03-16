//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Darwin
#elseif os(Windows)
import ucrt
import MSVCRT
import WinSDK
internal typealias sockaddr = WinSDK.SOCKADDR
internal typealias socklen_t = WinSDK.socklen_t
#else
import Glibc
#endif

enum Shutdown {
  case RD
  case WR
  case RDWR

  internal var cValue: CInt {
    switch self {
    case .RD:
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      return Darwin.SHUT_RD
#elseif os(Windows)
      return WinSDK.SD_RECEIVE
#else
      return CInt(Glibc.SHUT_RD)
#endif
    case .WR:
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      return Darwin.SHUT_WR
#elseif os(Windows)
      return WinSDK.SD_SEND
#else
      return CInt(Glibc.SHUT_WR)
#endif
    case .RDWR:
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      return Darwin.SHUT_RDWR
#elseif os(Windows)
      return WinSDK.SD_BOTH
#else
      return CInt(Glibc.SHUT_RDWR)
#endif
    }
  }
}

public enum BSDSocket {
#if os(Windows)
  public typealias Handle = SOCKET
#else
  public typealias Handle = CInt
#endif
}

// Socket Type
internal extension BSDSocket {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
  static let SOCK_DGRAM: CInt = CInt(Darwin.SOCK_DGRAM)
  static let SOCK_STREAM: CInt = CInt(Darwin.SOCK_STREAM)
#elseif os(Windows)
  static let SOCK_DGRAM: CInt = CInt(WinSDK.SOCK_DGRAM)
  static let SOCK_STREAM: CInt = CInt(WinSDK.SOCK_STREAM)
#else
#if os(Android)
  static let SOCK_DGRAM: CInt = CInt(Glibc.SOCK_DGRAM)
  static let SOCK_STREAM: CInt = CInt(Glibc.SOCK_STREAM)
#else
  static let SOCK_DGRAM: CInt = CInt(Glibc.SOCK_DGRAM.rawValue)
  static let SOCK_STREAM: CInt = CInt(Glibc.SOCK_STREAM.rawValue)
#endif
#endif
}

// Address Family
internal extension BSDSocket {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
  static let AF_INET: CInt = CInt(Darwin.AF_INET)
  static let AF_INET6: CInt = CInt(Darwin.AF_INET6)
  static let AF_UNIX: CInt = CInt(Darwin.AF_UNIX)
  static let AF_UNSPEC: CInt = CInt(Darwin.AF_UNSPEC)
#elseif os(Windows)
  static let AF_INET: CInt = CInt(WinSDK.AF_INET)
  static let AF_INET6: CInt = CInt(WinSDK.AF_INET6)
  static let AF_UNIX: CInt = CInt(WinSDK.AF_UNIX)
  static let AF_UNSPEC: CInt = CInt(WinSDK.AF_UNSPEC)
#else
  static let AF_INET: CInt = CInt(Glibc.AF_INET)
  static let AF_INET6: CInt = CInt(Glibc.AF_INET6)
  static let AF_UNIX: CInt = CInt(Glibc.AF_UNIX)
  static let AF_UNSPEC: CInt = CInt(Glibc.AF_UNSPEC)
#endif
}

// Packet Family
internal extension BSDSocket {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
  static let PF_INET: CInt = CInt(Darwin.PF_INET)
  static let PF_INET6: CInt = CInt(Darwin.PF_INET6)
  static let PF_UNIX: CInt = CInt(Darwin.PF_UNIX)
#elseif os(Windows)
  static let PF_INET: CInt = CInt(WinSDK.PF_INET)
  static let PF_INET6: CInt = CInt(WinSDK.PF_INET6)
  static let PF_UNIX: CInt = CInt(WinSDK.PF_UNIX)
#else
  static let PF_INET: CInt = CInt(Glibc.PF_INET)
  static let PF_INET6: CInt = CInt(Glibc.PF_INET6)
  static let PF_UNIX: CInt = CInt(Glibc.PF_UNIX)
#endif
}

internal extension BSDSocket {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
  static let IPPROTO_IP: CInt = CInt(Darwin.IPPROTO_IP)
  static let IPPROTO_IPV6: CInt = CInt(Darwin.IPPROTO_IPV6)
  static let IPPROTO_TCP: CInt = CInt(Darwin.IPPROTO_TCP)
  static let IPPROTO_UDP: CInt = CInt(Darwin.IPPROTO_UDP)
#elseif os(Windows)
  static let IPPROTO_IP: CInt = CInt(WinSDK.IPPROTO_IP)
  static let IPPROTO_IPV6: CInt = CInt(WinSDK.IPPROTO_IPV6.rawValue)
  static let IPPROTO_TCP: CInt = CInt(WinSDK.IPPROTO_TCP.rawValue)
  static let IPPROTO_UDP: CInt = CInt(WinSDK.IPPROTO_UDP.rawValue)
#else
  static let IPPROTO_IP: CInt = CInt(Glibc.IPPROTO_IP)
  static let IPPROTO_IPV6: CInt = CInt(Glibc.IPPROTO_IPV6)
  static let IPPROTO_TCP: CInt = CInt(Glibc.IPPROTO_TCP)
  static let IPPROTO_UDP: CInt = CInt(Glibc.IPPROTO_UDP)
#endif
}

// SocketOptionLevel
public extension BSDSocket {
  struct OptionLevel: Equatable {
    let rawValue: CInt

    // Protocol
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let IPPROTO_IP: OptionLevel = OptionLevel(rawValue: Darwin.IPPROTO_IP)
    static let IPPROTO_IPV6: OptionLevel = OptionLevel(rawValue: Darwin.IPPROTO_IPV6)
    static let IPPROTO_TCP: OptionLevel = OptionLevel(rawValue: Darwin.IPPROTO_TCP)
#elseif os(Windows)
    static let IPPROTO_IP: OptionLevel = OptionLevel(rawValue: WinSDK.IPPROTO_IP)
    static let IPPROTO_IPV6: OptionLevel = OptionLevel(rawValue: WinSDK.IPPROTO_IPV6.rawValue)
    static let IPPROTO_TCP: OptionLevel = OptionLevel(rawValue: WinSDK.IPPROTO_TCP.rawValue)
#else
    static let IPPROTO_IP: OptionLevel = OptionLevel(rawValue: CInt(Glibc.IPPROTO_IP))
    static let IPPROTO_IPV6: OptionLevel = OptionLevel(rawValue: CInt(Glibc.IPPROTO_IPV6))
    static let IPPROTO_TCP: OptionLevel = OptionLevel(rawValue: CInt(Glibc.IPPROTO_TCP))
#endif

    // Socket
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let SOL_SOCKET: OptionLevel = OptionLevel(rawValue: Darwin.SOL_SOCKET)
#elseif os(Windows)
    static let SOL_SOCKET: OptionLevel = OptionLevel(rawValue: WinSDK.SOL_SOCKET)
#else
    static let SOL_SOCKET: OptionLevel = OptionLevel(rawValue: Glibc.SOL_SOCKET)
#endif
  }
}

// SocketOption
public extension BSDSocket {
  struct Option: Equatable {
    let rawValue: CInt

    // IP Options
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let IP_ADD_MEMBERSHIP: Option = Option(rawValue: Darwin.IP_ADD_MEMBERSHIP)
    static let IP_DROP_MEMBERSHIP: Option = Option(rawValue: Darwin.IP_DROP_MEMBERSHIP)
    static let IP_MULTICAST_LOOP: Option = Option(rawValue: Darwin.IP_MULTICAST_LOOP)
    static let IP_MULTICAST_IF: Option = Option(rawValue: Darwin.IP_MULTICAST_IF)
    static let IP_MULTICAST_TTL: Option = Option(rawValue: Darwin.IP_MULTICAST_TTL)
#elseif os(Windows)
    static let IP_ADD_MEMBERSHIP: Option = Option(rawValue: WinSDK.IP_ADD_MEMBERSHIP)
    static let IP_DROP_MEMBERSHIP: Option = Option(rawValue: WinSDK.IP_DROP_MEMBERSHIP)
    static let IP_MULTICAST_LOOP: Option = Option(rawValue: WinSDK.IP_MULTICAST_LOOP)
    static let IP_MULTICAST_IF: Option = Option(rawValue: WinSDK.IP_MULTICAST_IF)
    static let IP_MULTICAST_TTL: Option = Option(rawValue: WinSDK.IP_MULTICAST_TTL)
#else
    static let IP_ADD_MEMBERSHIP: Option = Option(rawValue: Glibc.IP_ADD_MEMBERSHIP)
    static let IP_DROP_MEMBERSHIP: Option = Option(rawValue: Glibc.IP_DROP_MEMBERSHIP)
    static let IP_MULTICAST_LOOP: Option = Option(rawValue: Glibc.IP_MULTICAST_LOOP)
    static let IP_MULTICAST_IF: Option = Option(rawValue: Glibc.IP_MULTICAST_IF)
    static let IP_MULTICAST_TTL: Option = Option(rawValue: Glibc.IP_MULTICAST_TTL)
#endif

    // IPv6 Options
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let IPV6_JOIN_GROUP: Option = Option(rawValue: Darwin.IPV6_JOIN_GROUP)
    static let IPV6_LEAVE_GROUP: Option = Option(rawValue: Darwin.IPV6_LEAVE_GROUP)
    static let IPV6_MULTICAST_HOPS: Option = Option(rawValue: Darwin.IPV6_MULTICAST_HOPS)
    static let IPV6_MULTICAST_IF: Option = Option(rawValue: Darwin.IPV6_MULTICAST_IF)
    static let IPV6_MULTICAST_LOOP: Option = Option(rawValue: Darwin.IPV6_MULTICAST_LOOP)
    static let IPV6_V6ONLY: Option = Option(rawValue: Darwin.IPV6_V6ONLY)
#elseif os(Windows)
    static let IPV6_JOIN_GROUP: Option = Option(rawValue: WinSDK.IPV6_JOIN_GROUP)
    static let IPV6_LEAVE_GROUP: Option = Option(rawValue: WinSDK.IPV6_LEAVE_GROUP)
    static let IPV6_MULTICAST_HOPS: Option = Option(rawValue: WinSDK.IPV6_MULTICAST_HOPS)
    static let IPV6_MULTICAST_IF: Option = Option(rawValue: WinSDK.IPV6_MULTICAST_IF)
    static let IPV6_MULTICAST_LOOP: Option = Option(rawValue: WinSDK.IPV6_MULTICAST_LOOP)
    static let IPV6_V6ONLY: Option = Option(rawValue: WinSDK.IPV6_V6ONLY)
#else
    static let IPV6_JOIN_GROUP: Option = Option(rawValue: Glibc.IPV6_JOIN_GROUP)
    static let IPV6_LEAVE_GROUP: Option = Option(rawValue: Glibc.IPV6_LEAVE_GROUP)
    static let IPV6_MULTICAST_HOPS: Option = Option(rawValue: Glibc.IPV6_MULTICAST_HOPS)
    static let IPV6_MULTICAST_IF: Option = Option(rawValue: Glibc.IPV6_MULTICAST_IF)
    static let IPV6_MULTICAST_LOOP: Option = Option(rawValue: Glibc.IPV6_MULTICAST_LOOP)
    static let IPV6_V6ONLY: Option = Option(rawValue: Glibc.IPV6_V6ONLY)
#endif

    // TCP Options
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let TCP_NODELAY: Option = Option(rawValue: Darwin.TCP_NODELAY)
#elseif os(Windows)
    static let TCP_NODELAY: Option = Option(rawValue: WinSDK.TCP_NODELAY)
#else
    static let TCP_NODELAY: Option = Option(rawValue: Glibc.TCP_NODELAY)
#endif

    // Socket Options
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    static let SO_ERROR: Option = Option(rawValue: Darwin.SO_ERROR)
    static let SO_LINGER: Option = Option(rawValue: Darwin.SO_LINGER)
#elseif os(Windows)
    static let SO_ERROR: Option = Option(rawValue: WinSDK.SO_ERROR)
    static let SO_LINGER: Option = Option(rawValue: WinSDK.SO_LINGER)
#else
    static let SO_ERROR: Option = Option(rawValue: Glibc.SO_ERROR)
    static let SO_LINGER: Option = Option(rawValue: Glibc.SO_LINGER)
#endif
  }
}

private func _filter_errno(_ errno: CInt, where function: String) {
  // strerror is documented to return "Unknown error: ..." for illegal value so
  // it won't ever fail
  precondition(!(errno == EFAULT || errno == EBADF),
               "blacklisted errno \(errno) \(String(cString: strerror(errno)!)) in \(function)")
}

// syscall wrappers
internal extension BSDSocket {
  @inline(never)
  static func accept(socket s: BSDSocket.Handle,
                     address addr: UnsafeMutablePointer<sockaddr>?,
                     address_len addrlen: UnsafeMutablePointer<socklen_t>?)
      throws -> BSDSocket.Handle? {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    guard case let .processed(fd) = try syscall(blocking: true, { () -> BSDSocket.Handle in
      let fd = Darwin.accept(s, addr, addrlen)
      if fd == -1 { return fd }
      do {
        try Posix.fcntl(descriptor: fd, command: F_SETNOSIGPIPE, value: 1)
      } catch {
        _ = Darwin.close(fd)  // don't care about failure here
        throw error
      }
      return fd
    }) else {
      return nil
    }
    return fd
#elseif os(Windows)
      let socket: BSDSocket.Handle = WinSDK.accept(s, addr, addrlen)
      if socket == WinSDK.INVALID_SOCKET {
        throw IOError(WinSockError: WSAGetLastError(), reason: "accept")
      }
      return socket
#else
    guard case let .processed(fd) = try syscall(blocking: true, {
      Glibc.accept(s, addr, addrlen)
    }) else {
      return nil
    }
    return fd
#endif
  }

  @inline(never)
  static func bind(socket s: BSDSocket.Handle,
                   address addr: UnsafePointer<sockaddr>,
                   address_len namelen: socklen_t) throws {
#if os(Windows)
      if WinSDK.bind(s, addr, namelen) == SOCKET_ERROR {
        throw IOError(WinSockError: WSAGetLastError(), reason: "bind")
      }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let bind: (CInt, UnsafePointer<sockaddr>, socklen_t) -> CInt = Darwin.bind
#else
    let bind: (CInt, UnsafePointer<sockaddr>, socklen_t) -> CInt = Glibc.bind
#endif
    _ = try syscall(blocking: false) {
      bind(s, addr, namelen)
    }
#endif
  }

  @inline(never)
  static func close(socket s: BSDSocket.Handle) throws {
#if os(Windows)
    if WinSDK.closesocket(s) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "close")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let close: (CInt) -> CInt = Darwin.close
    let errno: CInt = Darwin.errno
#else
    let close: (CInt) -> CInt = Glibc.close
    let errno: CInt = Glibc.errno
#endif
    let result: CInt = close(s)
    if result == -1 {
      let errnoCode = errno
      if errnoCode == EINTR { return }
      _filter_errno(errnoCode, where: #function)
      throw IOError(errnoCode: errnoCode, reason: "close")
    }
#endif
  }

  @inline(never)
  static func connect(socket s: BSDSocket.Handle,
                      address name: UnsafePointer<sockaddr>,
                      address_len namelen: socklen_t)
      throws -> Bool {
#if os(Windows)
    if WinSDK.connect(s, name, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "connect")
    }
    return true
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let connect: (CInt, UnsafePointer<sockaddr>, socklen_t) -> CInt = Darwin.connect
#else
    let connect: (CInt, UnsafePointer<sockaddr>, socklen_t) -> CInt = Glibc.connect
#endif
    do {
      _ = try syscall(blocking: false) {
        connect(s, name, namelen)
      }
      return true
    } catch let error as IOError {
      if error.errnoCode == EINPROGRESS {
        return false
      }
      throw error
    }
#endif
  }

  @inline(never)
  static func getpeername(socket s: BSDSocket.Handle,
                          address name: UnsafeMutablePointer<sockaddr>,
                          address_len namelen: UnsafeMutablePointer<socklen_t>)
      throws {
#if os(Windows)
    if WinSDK.getpeername(s, name, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getpeername")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let getpeername: (CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> CInt = Darwin.getpeername
#else
    let getpeername: (CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> CInt = Glibc.getpeername
#endif
    _ = try syscall(blocking: false) {
      getpeername(s, name, namelen)
    }
#endif
  }

  @inline(never)
  static func getsockname(socket s: BSDSocket.Handle,
                          address name: UnsafeMutablePointer<sockaddr>,
                          address_len namelen: UnsafeMutablePointer<socklen_t>)
      throws {
#if os(Windows)
    if WinSDK.getsockname(s, name, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getsockname")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let getsockname: (CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> CInt = Darwin.getsockname
#else
    let getsockname: (CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> CInt = Glibc.getsockname
#endif
    _ = try syscall(blocking: false) {
      getsockname(s, name, namelen)
    }
#endif
  }

  @inline(never)
  static func getsockopt(socket: BSDSocket.Handle, level: BSDSocket.OptionLevel,
                         option_name optname: BSDSocket.Option,
                         option_value optval: UnsafeMutableRawPointer,
                         option_len optlen: UnsafeMutablePointer<socklen_t>)
      throws {
#if os(Windows)
    if WinSDK.getsockopt(socket, level.rawValue, optname.rawValue,
                         optval.assumingMemoryBound(to: CChar.self),
                         optlen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getsockopt")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let getsockopt: (CInt, CInt, CInt, UnsafeMutableRawPointer, UnsafeMutablePointer<socklen_t>) -> CInt = Darwin.getsockopt
#else
    let getsockopt: (CInt, CInt, CInt, UnsafeMutableRawPointer, UnsafeMutablePointer<socklen_t>) -> CInt = Glibc.getsockopt
#endif
    _ = try syscall(blocking: false) {
      getsockopt(socket, level.rawValue, optname.rawValue, optval, optlen)
    }
#endif
  }

  @inline(never)
  static func listen(socket s: BSDSocket.Handle, backlog: CInt) throws {
#if os(Windows)
    if WinSDK.listen(s, backlog) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "listen")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let listen: (CInt, CInt) -> CInt = Darwin.listen
#else
    let listen: (CInt, CInt) -> CInt = Glibc.listen
#endif
    _ = try syscall(blocking: false) {
      listen(s, backlog)
    }
#endif
  }

  @inline(never)
  static func recv(socket s: BSDSocket.Handle,
                   buffer buf: UnsafeMutableRawPointer, length len: size_t)
      throws -> IOResult<size_t> {
#if os(Windows)
    let iResult: CInt =
        WinSDK.recv(s, buf.assumingMemoryBound(to: CChar.self), CInt(len), 0)
    if iResult == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "recv")
    }
    return .processed(size_t(iResult))
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let recv: (CInt, UnsafeMutableRawPointer, size_t, CInt) -> ssize_t = Darwin.recv
#else
    let recv: (CInt, UnsafeMutableRawPointer, size_t, CInt) -> ssize_t = Glibc.recv
#endif
    return try syscall(blocking: true) {
      read(s, buf, len, 0)
    }
#endif
  }

  @inline(never)
  static func recvfrom(socket s: BSDSocket.Handle,
                       buffer buf: UnsafeMutableRawPointer, length len: size_t,
                       address from: UnsafeMutablePointer<sockaddr>,
                       address_len fromlen: UnsafeMutablePointer<socklen_t>)
      throws -> IOResult<size_t> {
#if os(Windows)
    let iResult: CInt =
        WinSDK.recvfrom(s, buf.assumingMemoryBound(to: CChar.self), CInt(len),
                        0, from, fromlen)
    if iResult == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "recvfrom")
    }
    return .processed(size_t(iResult))
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let recvfrom: (CInt, UnsafeMutableRawPointer, size_t, CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> ssize_t = Darwin.recvfrom
#else
    let recvfrom: (CInt, UnsafeMutableRawPointer, size_t, CInt, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> ssize_t = Glibc.recvfrom
#endif
    return try syscall(blocking: true) {
      recvfrom(s, buf, len, 0, from, fromlen)
    }
#endif
  }

  @inline(never)
  static func send(socket s: BSDSocket.Handle, buffer buf: UnsafeRawPointer,
                   length len: size_t) throws -> IOResult<size_t> {
#if os(Windows)
    let iResult: CInt =
        WinSDK.send(s, buf.assumingMemoryBound(to: CChar.self), CInt(len), 0)
    if iResult == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "send")
    }
    return .processed(size_t(iResult))
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let send: (CInt, UnsafeRawPointer, size_t, CInt) -> ssize_t = Darwin.setsockopt
#else
    let send: (CInt, UnsafeRawPointer, size_t, CInt) -> ssize_t = Glibc.setsockopt
#endif
    return try syscall(blocking: true) {
      send(s, buf, len, 0)
    }
#endif
  }

  @inline(never)
  static func setsockopt(socket: BSDSocket.Handle, level: BSDSocket.OptionLevel,
                         option_name optname: BSDSocket.Option,
                         option_value optval: UnsafeRawPointer,
                         option_len optlen: socklen_t) throws {
#if os(Windows)
    if WinSDK.setsockopt(socket, level.rawValue, optname.rawValue,
                         optval.assumingMemoryBound(to: CChar.self),
                         optlen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "setsockopt")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let setsockopt: (CInt, CInt, CInt, UnsafeRawPointer, socklen_t) -> CInt = Darwin.setsockopt
#else
    let setsockopt: (CInt, CInt, CInt, UnsafeRawPointer, socklen_t) -> CInt = Glibc.setsockopt
#endif
    _ = try syscall(blocking: false) {
      setsockopt(socket, level.rawValue, optname.rawValue, optval, optlen)
    }
#endif
  }

  // NOTE: this should return a `ssize_t`, however, that is not a standard type,
  // and defining that type is difficult.  Opt to return a `size_t` which is the
  // same size, but is unsigned.
  @inline(never)
  static func sendto(socket s: BSDSocket.Handle, buffer buf: UnsafeRawPointer,
                     length len: size_t, dest_addr to: UnsafePointer<sockaddr>,
                     dest_len tolen: socklen_t)
      throws -> IOResult<size_t> {
#if os(Windows)
    let iResult: CInt =
        WinSDK.sendto(s, buf.assumingMemoryBound(to: CChar.self), CInt(len), 0,
                      to, tolen)
    if iResult == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "sendto")
    }
    return .processed(size_t(iResult))
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let sendto: (CInt, UnsafeRawPointer, size_t, CInt, UnsafePointer<sockaddr>, socklen_t) -> ssize_t = Darwin.sendto
#else
    let sendto: (CInt, UnsafeRawPointer, size_t, CInt, UnsafePointer<sockaddr>, socklen_t) -> ssize_t = Glibc.sendto
#endif
    return try syscall(blocking: true) {
      sendto(s, buf, len, 0, to, tolen)
    }
#endif
  }

  @inline(never)
  static func shutdown(socket: BSDSocket.Handle, how: Shutdown) throws {
#if os(Windows)
    if WinSDK.shutdown(socket, how.cValue) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "shutdown")
    }
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let shutdown: (CInt, CInt) -> CInt = Darwin.shutdown
#else
    let shutdown: (CInt, CInt) -> CInt = Glibc.shutdown
#endif
    _ = try syscall(blocking: false) {
      shutdown(socket, how.cValue)
    }
#endif
  }

  @inline(never)
  static func socket(domain af: CInt, type: CInt, `protocol`: CInt)
      throws -> BSDSocket.Handle {
#if os(Windows)
    let socket: BSDSocket.Handle = WinSDK.socket(af, type, `protocol`)
    if socket == WinSDK.INVALID_SOCKET {
      throw IOError(WinSockError: WSAGetLastError(), reason: "socket")
    }
    return socket
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let socket: (CInt, CInt, CInt) -> CInt = Darwin.socket
#else
    let socket: (CInt, CInt, CInt) -> CInt = Glibc.socket
#endif
    return try syscall(blocking: false) {
      socket(af, type, `protocol`)
    }.result
#endif
  }
}

#if !os(Windows)
/*
 * Sorry, we really try hard to not use underscored attributes. In this case
 * however we seem to break the inlining threshold which makes a system call
 * take twice the time, ie. we need this exception.
 */
@inline(__always)
func wrapErrorIsNullReturnCall<T>(where function: String = #function,
                                  _ body: () throws -> T?) throws -> T {
  while true {
    guard let result = try body() else {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
      let errno = Darwin.errno
#else
      let errno = Glibc.errno
#endif
      if errno == EINTR { continue }
      _filter_errno(errno, where: function)
      throw IOError(errnoCode: errno, reason: function)
    }
    return result
  }
}
#endif

// TCP/IP Operations
internal extension BSDSocket {
  @discardableResult
  @inline(never)
  static func inet_ntop(af Family: CInt, src pAddr: UnsafeRawPointer,
                        dst pStringBuf: UnsafeMutablePointer<CChar>,
                        size StringBufSize: socklen_t)
      throws -> UnsafePointer<CChar> {
#if os(Windows)
    // TODO(compnerd) use `InetNtopW` to ensure that we handle unicode properly
    guard let result = WinSDK.inet_ntop(Family, pAddr, pStringBuf,
                                        Int(StringBufSize)) else {
      throw IOError(WindowsError: GetLastError(), reason: "inet_ntop")
    }
    return result
#else
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    let inet_ntop: (CInt, UnsafeRawPointer, UnsafeMutablePointer<CChar>, socklen_t) -> UnsafePointer<CChar> = Darwin.inet_ntop
#else
    let inet_ntop: (CInt, UnsafeRawPointer?, UnsafeMutablePointer<CChar>?, socklen_t) -> UnsafePointer<CChar>? = Glibc.inet_ntop
#endif
    return try wrapErrorIsNullReturnCall {
      inet_ntop(Family, pAddr, pStringBuf, StringBufSize)
    }
#endif
  }

  @inline(never)
  static func inet_pton(af Family: CInt,
                        src pszAddrString: UnsafePointer<CChar>,
                        dst pAddrBuf: UnsafeMutableRawPointer) throws {
#if os(Windows)
    // TODO(compnerd) use `InetPtonW` to ensure that we handle unicode properly
    switch WinSDK.inet_pton(Family, pszAddrString, pAddrBuf) {
    case 0: throw IOError(errnoCode: EINVAL, reason: "inet_pton")
    case 1: return
    default: throw IOError(WinSockError: WSAGetLastError(), reason: "inet_pton")
    }
#else
#endif
  }

  @inline(never)
  static func sendfile(socket s: BSDSocket.Handle, fd: CInt, offset: off_t,
                       len nNumberOfBytesToWrite: off_t)
      throws -> IOResult<CInt> {
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    var written: off_t = 0
    do {
      _ = try syscall(blocking: false) { () -> ssize_t in
        var w: off_t = off_t(count)
        let result: CInt = Darwin.sendfile(fd, descriptor, offset, &w, nil, 0)
        written = w
        return ssize_t(result)
      }
      return .processed(CInt(written))
    } catch let error as IOError {
      if error.errnoCode == EAGAIN {
        return .wouldBlock(CInt(written))
      }
      throw error
    }
#elseif os(Windows)
    let hFile: HANDLE = HANDLE(bitPattern: ucrt._get_osfhandle(fd))!
    if hFile == INVALID_HANDLE_VALUE {
      throw IOError(errnoCode: EBADF, reason: "_get_osfhandle")
    }
    var ovlOverlapped: OVERLAPPED = OVERLAPPED()
    ovlOverlapped.Offset = DWORD(UInt32(offset >> 0) & 0xffffffff)
    ovlOverlapped.OffsetHigh = DWORD(UInt32(offset >> 32) & 0xffffffff)
    if !TransmitFile(s, hFile, DWORD(nNumberOfBytesToWrite), 0, &ovlOverlapped,
                     nil, DWORD(TF_USE_KERNEL_APC)) {
      throw IOError(WinSockError: WSAGetLastError(), reason: "TransmitFile")
    }
    return .processed(CInt(nNumberOfBytesToWrite))
#else
    var written: off_t = 0
    do {
      _ = try syscall(blocking: false) { () -> ssize_t in
        var off: off_t = offset
        let result: ssize_t = Glibc.sendfile(descriptor, fd, &off, count)
        written = result >= 0 ? result : 0
        return result
      }
      return .processed(CInt(written))
    } catch let error as IOError {
      if error.errnoCode == EAGAIN {
        return .wouldBlock(CInt(written))
      }
      throw error
    }
#endif
  }
}

// Helper Functions
internal extension BSDSocket {
  static func setNonBlocking(socket: BSDSocket.Handle) throws {
#if os(Windows)
    var ulMode: u_long = 0
    if WinSDK.ioctlsocket(socket, FIONBIO, &ulMode) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "ioctlsocket")
    }
#else
    let flags = try Posix.fcntl(descriptor: socket, command: F_GETFL, value: 0)
    do {
      let ret = try Posix.fcntl(descriptor: socket, command: F_SETFL,
                                value: flags | O_NONBLOCK)
      assert(ret == 0, "unexpectedly, fcntl(\(socket), F_SETFL, \(flags) | O_NONBLOCK) returned \(ret)")
    } catch let error as IOError {
      if error.errnoCode == EINVAL {
        // Darwin seems to sometimes do this despite the docs claiming it can't
        // happen
        throw NIOFailedToSetSocketNonBlockingError()
      }
      throw error
    }
#endif
  }
}
