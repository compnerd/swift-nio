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

#if os(Linux) || os(FreeBSD) || os(Android)

@_exported
import Glibc
import CNIOLinux

internal typealias MMsgHdr = CNIOLinux_mmsghdr

#if os(Android)
let INADDR_ANY = UInt32(0) // #define INADDR_ANY ((unsigned long int) 0x00000000)

internal typealias sockaddr_storage = __kernel_sockaddr_storage
internal typealias in_port_t = UInt16

// http://lkml.iu.edu/hypermail/linux/kernel/0106.1/0080.html
extension ipv6_mreq {
    init (ipv6mr_multiaddr: in6_addr, ipv6mr_interface: UInt32) {
        self.ipv6mr_multiaddr = ipv6mr_multiaddr
        self.ipv6mr_ifindex = Int32(bitPattern: ipv6mr_interface)
    }
}
#endif

private func isBlacklistedErrno(_ code: Int32) -> Bool {
    switch code {
    case EFAULT, EBADF:
        return true
    default:
        return false
    }
}

private func preconditionIsNotBlacklistedErrno(err: CInt, where function: String) -> Void {
    // strerror is documented to return "Unknown error: ..." for illegal value so it won't ever fail
    precondition(!isBlacklistedErrno(err), "blacklisted errno \(err) \(String(cString: strerror(err)!)) in \(function))")
}

internal extension IOResult where T: FixedWidthInteger {
  var result: T! {
    get {
      switch self {
      case .processed(let result):
        return result
      default:
        return nil
      }
    }
  }
}

/*
 * Sorry, we really try hard to not use underscored attributes. In this case
 * however we seem to break the inlining threshold which makes a system call
 * take twice the time, ie. we need this exception.
 */
@inline(__always)
internal func call<T: FixedWidthInteger>(nonblocking: Bool,
                                         where function: String = #function,
                                         _ body: () throws -> T)
        throws -> IOResult<T> {
    while true {
        let res = try body()
        if res == -1 {
            let err = errno
            if err == EINTR { continue }
            if nonblocking == false && err == EWOULDBLOCK { return .wouldBlock(0) }
            preconditionIsNotBlacklistedErrno(err: err, where: function)
            throw IOError(errnoCode: err, reason: function)
        }
        return .processed(res)
    }
}

/*
 * Sorry, we really try hard to not use underscored attributes. In this case
 * however we seem to break the inlining threshold which makes a system call
 * take twice the time, ie. we need this exception.
 */
@inline(__always)
internal func wrapErrorIsNullReturnCall<T>(where function: String = #function,
                                           _ body: () throws -> T?) throws -> T {
    while true {
        guard let res = try body() else {
            let err = errno
            if err == EINTR {
                continue
            }
            preconditionIsNotBlacklistedErrno(err: err, where: function)
            throw IOError(errnoCode: err, reason: function)
        }
        return res
    }
}

enum Shutdown {
    case RD
    case WR
    case RDWR

    fileprivate var cValue: CInt {
        switch self {
        case .RD:
            return CInt(Glibc.SHUT_RD)
        case .WR:
            return CInt(Glibc.SHUT_WR)
        case .RDWR:
            return CInt(Glibc.SHUT_RDWR)
        }
    }
}

internal enum Posix {
#if os(Android)
    static let SOCK_STREAM: CInt = CInt(Glibc.SOCK_STREAM)
    static let SOCK_DGRAM: CInt = CInt(Glibc.SOCK_DGRAM)
#else
    static let SOCK_STREAM: CInt = CInt(Glibc.SOCK_STREAM.rawValue)
    static let SOCK_DGRAM: CInt = CInt(Glibc.SOCK_DGRAM.rawValue)
#endif
    static let IPPROTO_TCP: CInt = CInt(Glibc.IPPROTO_TCP)
    static let UIO_MAXIOV: Int = Int(Glibc.UIO_MAXIOV)

    static let AF_INET: sa_family_t = sa_family_t(Glibc.AF_INET)
    static let AF_INET6: sa_family_t = sa_family_t(Glibc.AF_INET6)
    static let AF_UNIX: sa_family_t = sa_family_t(Glibc.AF_UNIX)

    static let PF_INET = Glibc.PF_INET
    static let PF_INET6 = Glibc.PF_INET6
    static let PF_UNIX = Glibc.PF_UNIX

    @inline(never)
    public static func shutdown(descriptor: CInt, how: Shutdown) throws {
        _ = try call(nonblocking: true) {
            Glibc.shutdown(descriptor, how.cValue)
        }
    }

    @inline(never)
    public static func close(descriptor: CInt) throws {
        let res = Glibc.close(descriptor)
        if res == -1 {
            let err = errno

            // There is really nothing "sane" we can do when EINTR was reported on close.
            // So just ignore it and "assume" everything is fine == we closed the file descriptor.
            //
            // For more details see:
            //     - https://bugs.chromium.org/p/chromium/issues/detail?id=269623
            //     - https://lwn.net/Articles/576478/
            if err != EINTR {
                preconditionIsNotBlacklistedErrno(err: err, where: #function)
                throw IOError(errnoCode: err, reason: "close")
            }
        }
    }

    @inline(never)
    public static func bind(descriptor: CInt, ptr: UnsafePointer<sockaddr>, bytes: Int) throws {
         _ = try call(nonblocking: true) {
            Glibc.bind(descriptor, ptr, socklen_t(bytes))
        }
    }

    @inline(never)
    @discardableResult
    // TODO: Allow varargs
    public static func fcntl(descriptor: CInt, command: CInt, value: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Glibc.fcntl(descriptor, command, value)
        }.result
    }

    @inline(never)
    public static func socket(domain: CInt, type: CInt, `protocol`: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            return Glibc.socket(domain, type, `protocol`)
        }.result
    }

    @inline(never)
    public static func setsockopt(socket: CInt, level: CInt, optionName: CInt,
                                  optionValue: UnsafeRawPointer, optionLen: socklen_t) throws {
        _ = try call(nonblocking: true) {
            Glibc.setsockopt(socket, level, optionName, optionValue, optionLen)
        }
    }

    @inline(never)
    public static func getsockopt(socket: CInt, level: CInt, optionName: CInt,
                                  optionValue: UnsafeMutableRawPointer, optionLen: UnsafeMutablePointer<socklen_t>) throws {
         _ = try call(nonblocking: true) {
            Glibc.getsockopt(socket, level, optionName, optionValue, optionLen)
        }
    }

    @inline(never)
    public static func listen(descriptor: CInt, backlog: CInt) throws {
        _ = try call(nonblocking: true) {
            Glibc.listen(descriptor, backlog)
        }
    }

    @inline(never)
    public static func accept(descriptor: CInt,
                              addr: UnsafeMutablePointer<sockaddr>?,
                              len: UnsafeMutablePointer<socklen_t>?) throws -> CInt? {
        let result: IOResult<CInt> = try call(nonblocking: false) {
            let fd = Glibc.accept(descriptor, addr, len)

            #if !os(Linux)
                if fd != -1 {
                    do {
                        try Posix.fcntl(descriptor: fd, command: F_SETNOSIGPIPE, value: 1)
                    } catch {
                        _ = Glibc.close(fd) // don't care about failure here
                        throw error
                    }
                }
            #endif
            return fd
        }

        if case .processed(let fd) = result {
            return fd
        } else {
            return nil
        }
    }

    @inline(never)
    public static func connect(descriptor: CInt, addr: UnsafePointer<sockaddr>, size: socklen_t) throws -> Bool {
        do {
            _ = try call(nonblocking: true) {
                Glibc.connect(descriptor, addr, size)
            }
            return true
        } catch let err as IOError {
            if err.errnoCode == EINPROGRESS {
                return false
            }
            throw err
        }
    }

    @inline(never)
    public static func open(file: UnsafePointer<CChar>, oFlag: CInt, mode: mode_t) throws -> CInt {
        return try call(nonblocking: true) {
            Glibc.open(file, oFlag, mode)
        }.result
    }

    @inline(never)
    public static func open(file: UnsafePointer<CChar>, oFlag: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Glibc.open(file, oFlag)
        }.result
    }

    @inline(never)
    public static func write(descriptor: CInt, pointer: UnsafeRawPointer, size: Int) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Glibc.write(descriptor, pointer, size)
        }
    }

    @inline(never)
    public static func writev(descriptor: CInt, iovecs: UnsafeBufferPointer<IOVector>) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Glibc.writev(descriptor, iovecs.baseAddress!, CInt(iovecs.count))
        }
    }

    @inline(never)
    public static func sendto(descriptor: CInt, pointer: UnsafeRawPointer, size: size_t,
                              destinationPtr: UnsafePointer<sockaddr>, destinationSize: socklen_t) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Glibc.sendto(descriptor, pointer, size, 0, destinationPtr, destinationSize)
        }
    }

    @inline(never)
    public static func read(descriptor: CInt, pointer: UnsafeMutableRawPointer, size: size_t) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Glibc.read(descriptor, pointer, size)
        }
    }

    @inline(never)
    public static func pread(descriptor: CInt, pointer: UnsafeMutableRawPointer, size: size_t, offset: off_t) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Glibc.pread(descriptor, pointer, size, offset)
        }
    }

    @inline(never)
    public static func recvfrom(descriptor: CInt, pointer: UnsafeMutableRawPointer, len: size_t, addr: UnsafeMutablePointer<sockaddr>, addrlen: UnsafeMutablePointer<socklen_t>) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Glibc.recvfrom(descriptor, pointer, len, 0, addr, addrlen)
        }
    }

    @discardableResult
    @inline(never)
    public static func lseek(descriptor: CInt, offset: off_t, whence: CInt) throws -> off_t {
        return try call(nonblocking: true) {
            Glibc.lseek(descriptor, offset, whence)
        }.result
    }

    @discardableResult
    @inline(never)
    public static func dup(descriptor: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Glibc.dup(descriptor)
        }.result
    }

    @discardableResult
    @inline(never)
    public static func inet_ntop(addressFamily: CInt, addressBytes: UnsafeRawPointer, addressDescription: UnsafeMutablePointer<CChar>, addressDescriptionLength: socklen_t) throws -> UnsafePointer<CChar> {
        return try wrapErrorIsNullReturnCall {
            Glibc.inet_ntop(addressFamily, addressBytes, addressDescription, addressDescriptionLength)
        }
    }

    @inline(never)
    public static func inet_pton(_ af: CInt, _ src: UnsafePointer<CChar>,
                                 _ dst: UnsafeMutableRawPointer) throws {
        switch try call(nonblocking: true, { Glibc.inet_pton(af, src, dst) }).result {
        case 0: throw IOError(errno: EINVAL, reason: "inet_pton")
        case 1: return
        default: break
        }
        throw IOError(errnoCode: errno, reason: "inet_pton")
    }

    // It's not really posix but exists on Linux and MacOS / BSD so just put it here for now to keep it simple
    @inline(never)
    public static func sendfile(descriptor: CInt, fd: CInt, offset: off_t, count: size_t) throws -> IOResult<Int> {
        var written: off_t = 0
        do {
            _ = try call(nonblocking: true) { () -> ssize_t in
                var off: off_t = offset
                let result: ssize_t = Glibc.sendfile(descriptor, fd, &off, count)
                if result >= 0 {
                    written = result
                } else {
                    written = 0
                }
                return result
            }
            return .processed(Int(written))
        } catch let err as IOError {
            if err.errnoCode == EAGAIN {
                return .wouldBlock(Int(written))
            }
            throw err
        }
    }

    @inline(never)
    public static func sendmmsg(sockfd: CInt, msgvec: UnsafeMutablePointer<MMsgHdr>, vlen: CUnsignedInt, flags: CInt) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Int(CNIOLinux_sendmmsg(sockfd, msgvec, vlen, flags))
        }
    }

    @inline(never)
    public static func recvmmsg(sockfd: CInt, msgvec: UnsafeMutablePointer<MMsgHdr>, vlen: CUnsignedInt, flags: CInt, timeout: UnsafeMutablePointer<timespec>?) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Int(CNIOLinux_recvmmsg(sockfd, msgvec, vlen, flags, timeout))
        }
    }

    @inline(never)
    public static func getpeername(socket: CInt, address: UnsafeMutablePointer<sockaddr>, addressLength: UnsafeMutablePointer<socklen_t>) throws {
        _ = try call(nonblocking: true) {
            return Glibc.getpeername(socket, address, addressLength)
        }
    }

    @inline(never)
    public static func getsockname(socket: CInt, address: UnsafeMutablePointer<sockaddr>, addressLength: UnsafeMutablePointer<socklen_t>) throws {
        _ = try call(nonblocking: true) {
            return Glibc.getsockname(socket, address, addressLength)
        }
    }

    @inline(never)
    public static func getifaddrs(_ addrs: UnsafeMutablePointer<UnsafeMutablePointer<ifaddrs>?>) throws {
        _ = try call(nonblocking: true) {
            Glibc.getifaddrs(addrs)
        }
    }

    @inline(never)
    public static func if_nametoindex(_ name: UnsafePointer<CChar>?) throws -> CUnsignedInt {
        return try call(nonblocking: true) {
            Glibc.if_nametoindex(name)
        }.result
    }

    @inline(never)
    public static func poll(fds: UnsafeMutablePointer<pollfd>, nfds: nfds_t, timeout: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Glibc.poll(fds, nfds, timeout)
        }.result
    }

    @inline(never)
    public static func fstat(descriptor: CInt, outStat: UnsafeMutablePointer<stat>) throws {
        _ = try call(nonblocking: true) {
            Glibc.fstat(descriptor, outStat)
        }
    }

    @inline(never)
    public static func socketpair(domain: CInt,
                                  type: CInt,
                                  protocol: CInt,
                                  socketVector: UnsafeMutablePointer<CInt>?) throws {
        _ = try call(nonblocking: true) {
            Glibc.socketpair(domain, type, `protocol`, socketVector)
        }
    }


    @inline(never)
    public static func freeifaddrs(_ addrs: UnsafeMutablePointer<ifaddrs>?) {
#if os(Android)
      android_freeifaddrs(addrs)
#else
      Glibc.freeifaddrs(addrs)
#endif
    }

    @inline(never)
    public static func getaddrinfo(_ node: UnsafePointer<CChar>,
                                   _ service: UnsafePointer<CChar>,
                                   _ hints: UnsafePointer<addrinfo>?,
                                   _ res: UnsafeMutablePointer<UnsafeMutablePointer<addrinfo>?>?)
        throws {
      /* FIXME: this is blocking! */
      let result = Glibc.getaddrinfo(node, service, hints, res)
      if result == 0 { return }
      throw IOError(errnoCode: result, reason: "getaddrinfo")
    }

    @inline(never)
    public static func freeaddrinfo(_ res: UnsafeMutablePointer<addrinfo>?) {
      Glibc.freeaddrinfo(res)
    }
}

#endif
