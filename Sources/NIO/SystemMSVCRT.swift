//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

//
//  This file contains code that ensures errno is captured correctly when doing
//  syscalls and no ARC traffic can happen inbetween that *could* change the
//  errno value before we were able to read it.  It's important that all static
//  methods are declared with `@inline(never)` so it's not possible any ARC
//  traffic happens while we need to read errno.
//
//  Created by Norman Maurer on 11/10/17.
//

#if os(Windows)

@_exported
import ucrt
import MSVCRT
import WinSDK
import CNIOWindows

internal typealias MMsgHdr = CNIOWindows_mmsghdr

internal typealias in_addr = IN_ADDR
internal typealias in6_addr = IN6_ADDR

internal typealias in_port_t = UInt16

internal typealias linger = LINGER

internal typealias sockaddr = SOCKADDR
internal typealias sockaddr_in = SOCKADDR_IN
internal typealias sockaddr_in6 = SOCKADDR_IN6

internal typealias sockaddr_storage = SOCKADDR_STORAGE

internal typealias socklen_t = WinSDK.socklen_t

internal typealias sa_family_t = ADDRESS_FAMILY

internal typealias addrinfo = ADDRINFOA

internal extension IN_ADDR {
  var s_addr: UInt32 { self.S_un.S_addr }
}

internal let INET_ADDRSTRLEN = WinSDK.INET_ADDRSTRLEN
internal let INET6_ADDRSTRLEN = WinSDK.INET6_ADDRSTRLEN

private func _filter_errno(_ errno: CInt, _ function: String) {
  // strerror is documented to return "Unknown error: ..." for illegal value so it won't ever fail
  precondition(!(errno == EFAULT || errno == EBADF),
               "blacklisted errno \(errno) \(String(cString: strerror(errno)!)) in \(function)")
}

fileprivate extension IOResult where T: FixedWidthInteger {
  var result: T! {
    switch self {
    case .processed(let value):
      return value
    default:
      return nil
    }
  }
}

/*
 * Sorry, we really try hard to not use underscored attributes. In this case
 * however we seem to break the inlining threshold which makes a system call
 * take twice the time, ie. we need this exception.
 */
@inline(__always)
internal func call<T: FixedWidthInteger>(blocking: Bool = true,
                                         where function: String = #function,
                                         _ body: () throws -> T)
    throws -> IOResult<T> {
  while true {
    let result: T = try body()
    if result != -1 { return .processed(result) }

    let errno = MSVCRT.errno
    if errno == EINTR { continue }
    if blocking && errno == EWOULDBLOCK { return .wouldBlock(0) }
    _filter_errno(errno, function)
    throw IOError(errno: errno, reason: function)
  }
}

enum Shutdown {
case RD
case WR
case RDWR
}

extension Shutdown {
  fileprivate var cValue: CInt {
    switch self {
    case .RD: return CInt(WinSDK.SD_RECEIVE)
    case .WR: return CInt(WinSDK.SD_SEND)
    case .RDWR: return CInt(WinSDK.SD_BOTH)
    }
  }
}

internal enum Posix {
  static let SOCK_DGRAM: CInt = CInt(WinSDK.SOCK_DGRAM)
  static let SOCK_STREAM: CInt = CInt(WinSDK.SOCK_STREAM)

  static let IPPROTO_IP: CInt = CInt(WinSDK.IPPROTO_IP)
  static let IPPROTO_IPV6: CInt = CInt(WinSDK.IPPROTO_IPV6.rawValue)
  static let IPPROTO_TCP: CInt = CInt(WinSDK.IPPROTO_TCP.rawValue)

  static let AF_INET: sa_family_t = sa_family_t(WinSDK.AF_INET)
  static let AF_INET6: sa_family_t = sa_family_t(WinSDK.AF_INET6)

  static let PF_INET: CInt = CInt(WinSDK.PF_INET)
  static let PF_INET6: CInt = CInt(WinSDK.PF_INET6)

  @inline(never)
  public static func accept(socket s: SOCKET,
                            addr: UnsafeMutablePointer<sockaddr>?,
                            len addrlen: UnsafeMutablePointer<socklen_t>?)
      throws -> SOCKET {
    let socket: SOCKET = WinSDK.accept(s, addr, addrlen)
    if socket == INVALID_SOCKET {
      throw IOError(WinSockError: WSAGetLastError(), reason: "accept")
    }
    return socket
  }

  @inline(never)
  public static func bind(socket s: SOCKET, ptr addr: UnsafePointer<sockaddr>,
                          bytes namelen: CInt) throws {
    if WinSDK.bind(s, addr, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "bind")
    }
  }

  @inline(never)
  public static func close(descriptor: CInt) throws {
    if ucrt._close(descriptor) == -1 {
      let errno = MSVCRT.errno
      if errno == EINTR { return }
      _filter_errno(errno, "close")
      throw IOError(errno: errno, reason: "close")
    }
  }

  @inline(never)
  public static func close(socket: SOCKET) throws {
    if WinSDK.closesocket(socket) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "closesocket")
    }
  }

  @inline(never)
  public static func connect(socket: SOCKET, addr name: UnsafePointer<sockaddr>,
                             size namelen: socklen_t) throws -> Bool {
    let result: CInt = WinSDK.connect(socket, name, namelen)
    if result == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "connect")
    }
    return true
  }

  @inline(never)
  public static func dup(descriptor: CInt) throws -> CInt {
    return try call(blocking: false) { ucrt._dup(descriptor) }.result
  }

  @inline(never)
  public static func freeaddrinfo(_ pAddrInfo: UnsafeMutablePointer<ADDRINFO>?) {
    WinSDK.freeaddrinfo(pAddrInfo)
  }

  @inline(never)
  public static func fstat(descriptor fd: CInt,
                           outStat buffer: UnsafeMutablePointer<stat>) throws {
    _ = try call(blocking: false) { ucrt.fstat(fd, buffer) }
  }

  @inline(never)
  public static func getaddrinfo(_ pNodeName: UnsafePointer<CChar>,
                                 _ pServiceName: UnsafePointer<CChar>,
                                 _ pHints: UnsafePointer<ADDRINFOA>?,
                                 _ ppResult: UnsafeMutablePointer<UnsafeMutablePointer<ADDRINFOA>?>?)
      throws {
    let iResult = WinSDK.getaddrinfo(pNodeName, pServiceName, pHints, ppResult)
    if iResult == 0 { return }
    throw IOError(WinSockError: iResult, reason: "getaddrinfo")
  }

  @inline(never)
  public static func getpeername(socket s: SOCKET,
                                 address name: UnsafeMutablePointer<sockaddr>,
                                 addressLength namelen: UnsafeMutablePointer<socklen_t>)
      throws {
    if WinSDK.getpeername(s, name, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getpeername")
    }
  }

  @inline(never)
  public static func getsockname(socket s: SOCKET,
                                 address name: UnsafeMutablePointer<sockaddr>,
                                 addressLength namelen: UnsafeMutablePointer<socklen_t>)
      throws {
    if WinSDK.getsockname(s, name, namelen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getsockname")
    }
  }

  @inline(never)
  public static func getsockopt(socket s: SOCKET, level: CInt,
                                optionName optname: CInt,
                                optionValue optval: UnsafeMutablePointer<CChar>,
                                optionLen optlen: UnsafeMutablePointer<CInt>)
      throws {
    if WinSDK.getsockopt(s, level, optname, optval, optlen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "getsockopt")
    }
  }

  @discardableResult
  @inline(never)
  public static func inet_ntop(addressFamily Family: CInt,
                               addressBytes pAddr: UnsafeRawPointer,
                               addressDescription pStringBuf: UnsafeMutablePointer<CChar>,
                               addressDescriptionLength StringBufSize: socklen_t)
      throws -> UnsafePointer<CChar> {
    // TODO(compnerd) use InetNtopW
    guard let result = WinSDK.inet_ntop(Family, pAddr, pStringBuf, size_t(StringBufSize)) else {
      throw IOError(WindowsError: GetLastError(), reason: "inet_ntop")
    }
    return result
  }

  @inline(never)
  public static func inet_pton(_ Family: CInt,
                               _ pszAddrString: UnsafePointer<CChar>,
                               _ pAddrBuf: UnsafeMutableRawPointer) throws {
    switch WinSDK.inet_pton(Family, pszAddrString, pAddrBuf) {
    case 0: throw IOError(errno: EINVAL, reason: "inet_pton")
    case 1: return
    default: break
    }
    throw IOError(WinSockError: WSAGetLastError(), reason: "inet_pton")
  }

  @inline(never)
  public static func listen(socket s: SOCKET, backlog: CInt) throws {
    if WinSDK.listen(s, backlog) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "listen")
    }
  }

  @discardableResult
  @inline(never)
  public static func lseek(descriptor fd: CInt, offset: CLong,
                           whence origin: CInt) throws -> CLong {
    // FIXME(compnerd) should this use _lseeki64 (CInt:Int64,CInt) -> Int64
    return try call(blocking: false) { ucrt._lseek(fd, offset, origin) }.result
  }

  @inline(never)
  public static func read(descriptor fd: CInt,
                          pointer buffer: UnsafeMutableRawPointer,
                          size buffer_size: CUnsignedInt)
      throws -> IOResult<CInt> {
    return try call(blocking: true) { ucrt._read(fd, buffer, buffer_size) }
  }

  @inline(never)
  public static func setsockopt(socket s: SOCKET, level: CInt,
                                optionName optname: CInt,
                                optionValue optval: UnsafePointer<CChar>,
                                optionLen optlen: CInt) throws {
    if WinSDK.setsockopt(s, level, optname, optval, optlen) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "setsockopt")
    }
  }

  @inline(never)
  public static func shutdown(socket: SOCKET, how: Shutdown) throws {
    if WinSDK.shutdown(socket, how.cValue) == SOCKET_ERROR {
      throw IOError(WinSockError: WSAGetLastError(), reason: "shutdown")
    }
  }

  @inline(never)
  public static func socket(domain af: CInt, type: CInt, `protocol`: CInt)
      throws -> SOCKET {
    let socket = WinSDK.socket(af, type, `protocol`)
    if socket == INVALID_SOCKET {
      throw IOError(WinSockError: WSAGetLastError(), reason: "socket")
    }
    return socket
  }

  @inline(never)
  public static func write(descriptor fd: CInt,
                           pointer buffer: UnsafeRawPointer,
                           size count: CUnsignedInt) throws -> IOResult<CInt> {
    return try call(blocking: true) { ucrt._write(fd, buffer, count) }
  }
}

#endif
