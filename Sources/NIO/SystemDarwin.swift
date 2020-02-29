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

#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)

@_exported
import Darwin.C
import CNIODarwin

// FIXME(compnerd) why is this needed?
private let sysKevent = kevent

internal typealias MMsgHdr = CNIODarwin_mmsghdr

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

fileprivate extension IOResult where T: Equatable {
  var result: T {
    get {
      switch self {
      case .processed(let result):
        return result
      default:
        fatalError("nonblock call cannot have the result unwrapped")
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
internal func call<T: FixedWidthInteger>(nonblocking: Bool, where function: String = #function, _ body: () throws -> T) throws -> IOResult<T> {
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
internal func wrapErrorIsNullReturnCall<T>(where function: String = #function, _ body: () throws -> T?) throws -> T {
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
            return CInt(Darwin.SHUT_RD)
        case .WR:
            return CInt(Darwin.SHUT_WR)
        case .RDWR:
            return CInt(Darwin.SHUT_RDWR)
        }
    }
}

internal enum Posix {
    static let SOCK_STREAM: CInt = CInt(Darwin.SOCK_STREAM)
    static let SOCK_DGRAM: CInt = CInt(Darwin.SOCK_DGRAM)
    static let IPPROTO_TCP: CInt = CInt(Darwin.IPPROTO_TCP)
    static let UIO_MAXIOV: Int = 1024

    static let AF_INET = sa_family_t(Darwin.AF_INET)
    static let AF_INET6 = sa_family_t(Darwin.AF_INET6)
    static let AF_UNIX = sa_family_t(Darwin.AF_UNIX)

    @inline(never)
    public static func shutdown(descriptor: CInt, how: Shutdown) throws {
        _ = try call(nonblocking: true) {
            Darwin.shutdown(descriptor, how.cValue)
        }
    }

    @inline(never)
    public static func close(descriptor: CInt) throws {
        let res = Darwin.close(descriptor)
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
            Darwin.bind(descriptor, ptr, socklen_t(bytes))
        }
    }

    @inline(never)
    @discardableResult
    // TODO: Allow varargs
    public static func fcntl(descriptor: CInt, command: CInt, value: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Darwin.fcntl(descriptor, command, value)
        }.result
    }

    @inline(never)
    public static func socket(domain: CInt, type: CInt, `protocol`: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            return Darwin.socket(domain, type, `protocol`)
        }.result
    }

    @inline(never)
    public static func setsockopt(socket: CInt, level: CInt, optionName: CInt,
                                  optionValue: UnsafeRawPointer, optionLen: socklen_t) throws {
        _ = try call(nonblocking: true) {
            Darwin.setsockopt(socket, level, optionName, optionValue, optionLen)
        }
    }

    @inline(never)
    public static func getsockopt(socket: CInt, level: CInt, optionName: CInt,
                                  optionValue: UnsafeMutableRawPointer, optionLen: UnsafeMutablePointer<socklen_t>) throws {
         _ = try call(nonblocking: true) {
            Darwin.getsockopt(socket, level, optionName, optionValue, optionLen)
        }
    }

    @inline(never)
    public static func listen(descriptor: CInt, backlog: CInt) throws {
        _ = try call(nonblocking: true) {
            Darwin.listen(descriptor, backlog)
        }
    }

    @inline(never)
    public static func accept(descriptor: CInt,
                              addr: UnsafeMutablePointer<sockaddr>?,
                              len: UnsafeMutablePointer<socklen_t>?) throws -> CInt? {
        if case .processed(let fd) = try call(nonblocking: false, { () throws -> CInt in
            let fd = Darwin.accept(descriptor, addr, len)
            if fd != -1 {
                do {
                    try Posix.fcntl(descriptor: fd, command: F_SETNOSIGPIPE, value: 1)
                } catch {
                    _ = Darwin.close(fd) // don't care about failure here
                    throw error
                }
            }
            return fd
        }) {
          return fd
        }

        return nil
    }

    @inline(never)
    public static func connect(descriptor: CInt, addr: UnsafePointer<sockaddr>, size: socklen_t) throws -> Bool {
        do {
            _ = try call(nonblocking: true) {
                Darwin.connect(descriptor, addr, size)
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
            Darwin.open(file, oFlag, mode)
        }.result
    }

    @inline(never)
    public static func open(file: UnsafePointer<CChar>, oFlag: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Darwin.open(file, oFlag)
        }.result
    }

    @inline(never)
    public static func write(descriptor: CInt, pointer: UnsafeRawPointer, size: Int) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Darwin.write(descriptor, pointer, size)
        }
    }

    @inline(never)
    public static func writev(descriptor: CInt, iovecs: UnsafeBufferPointer<IOVector>) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Darwin.writev(descriptor, iovecs.baseAddress!, CInt(iovecs.count))
        }
    }

    @inline(never)
    public static func sendto(descriptor: CInt, pointer: UnsafeRawPointer, size: size_t,
                              destinationPtr: UnsafePointer<sockaddr>, destinationSize: socklen_t) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Darwin.sendto(descriptor, pointer, size, 0, destinationPtr, destinationSize)
        }
    }

    @inline(never)
    public static func read(descriptor: CInt, pointer: UnsafeMutableRawPointer, size: size_t) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Darwin.read(descriptor, pointer, size)
        }
    }

    @inline(never)
    public static func pread(descriptor: CInt, pointer: UnsafeMutableRawPointer, size: size_t, offset: off_t) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Darwin.pread(descriptor, pointer, size, offset)
        }
    }

    @inline(never)
    public static func recvfrom(descriptor: CInt, pointer: UnsafeMutableRawPointer, len: size_t, addr: UnsafeMutablePointer<sockaddr>, addrlen: UnsafeMutablePointer<socklen_t>) throws -> IOResult<ssize_t> {
        return try call(nonblocking: false) {
            Darwin.recvfrom(descriptor, pointer, len, 0, addr, addrlen)
        }
    }

    @discardableResult
    @inline(never)
    public static func lseek(descriptor: CInt, offset: off_t, whence: CInt) throws -> off_t {
        return try call(nonblocking: true) {
            Darwin.lseek(descriptor, offset, whence)
        }.result
    }

    @discardableResult
    @inline(never)
    public static func dup(descriptor: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Darwin.dup(descriptor)
        }.result
    }

    @discardableResult
    @inline(never)
    public static func inet_ntop(addressFamily: CInt, addressBytes: UnsafeRawPointer, addressDescription: UnsafeMutablePointer<CChar>, addressDescriptionLength: socklen_t) throws -> UnsafePointer<CChar> {
        return try wrapErrorIsNullReturnCall {
            Darwin.inet_ntop(addressFamily, addressBytes, addressDescription, addressDescriptionLength)
        }
    }

    // It's not really posix but exists on Linux and MacOS / BSD so just put it here for now to keep it simple
    @inline(never)
    public static func sendfile(descriptor: CInt, fd: CInt, offset: off_t, count: size_t) throws -> IOResult<Int> {
        var written: off_t = 0
        do {
            _ = try call(nonblocking: true) { () -> ssize_t in
                var w: off_t = off_t(count)
                let result: CInt = Darwin.sendfile(fd, descriptor, offset, &w, nil, 0)
                written = w
                return ssize_t(result)
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
            Int(CNIODarwin_sendmmsg(sockfd, msgvec, vlen, flags))
        }
    }

    @inline(never)
    public static func recvmmsg(sockfd: CInt, msgvec: UnsafeMutablePointer<MMsgHdr>, vlen: CUnsignedInt, flags: CInt, timeout: UnsafeMutablePointer<timespec>?) throws -> IOResult<Int> {
        return try call(nonblocking: false) {
            Int(CNIODarwin_recvmmsg(sockfd, msgvec, vlen, flags, timeout))
        }
    }

    @inline(never)
    public static func getpeername(socket: CInt, address: UnsafeMutablePointer<sockaddr>, addressLength: UnsafeMutablePointer<socklen_t>) throws {
        _ = try call(nonblocking: true) {
            return Darwin.getpeername(socket, address, addressLength)
        }
    }

    @inline(never)
    public static func getsockname(socket: CInt, address: UnsafeMutablePointer<sockaddr>, addressLength: UnsafeMutablePointer<socklen_t>) throws {
        _ = try call(nonblocking: true) {
            return Darwin.getsockname(socket, address, addressLength)
        }
    }

    @inline(never)
    public static func getifaddrs(_ addrs: UnsafeMutablePointer<UnsafeMutablePointer<ifaddrs>?>) throws {
        _ = try call(nonblocking: true) {
            Darwin.getifaddrs(addrs)
        }
    }

    @inline(never)
    public static func if_nametoindex(_ name: UnsafePointer<CChar>?) throws -> CUnsignedInt {
        return try call(nonblocking: true) {
            Darwin.if_nametoindex(name)
        }.result
    }

    @inline(never)
    public static func poll(fds: UnsafeMutablePointer<pollfd>, nfds: nfds_t, timeout: CInt) throws -> CInt {
        return try call(nonblocking: true) {
            Darwin.poll(fds, nfds, timeout)
        }.result
    }

    @inline(never)
    public static func fstat(descriptor: CInt, outStat: UnsafeMutablePointer<stat>) throws {
        _ = try call(nonblocking: true) {
            Darwin.fstat(descriptor, outStat)
        }
    }

    @inline(never)
    public static func socketpair(domain: CInt,
                                  type: CInt,
                                  protocol: CInt,
                                  socketVector: UnsafeMutablePointer<CInt>?) throws {
        _ = try call(nonblocking: true) {
            Darwin.socketpair(domain, type, `protocol`, socketVector)
        }
    }
}

internal enum KQueue {

    // TODO: Figure out how to specify a typealias to the kevent struct without run into trouble with the swift compiler

    @inline(never)
    public static func kqueue() throws -> CInt {
        return try call(nonblocking: true) {
            Darwin.kqueue()
        }.result
    }

    @inline(never)
    @discardableResult
    public static func kevent(kq: CInt, changelist: UnsafePointer<kevent>?, nchanges: CInt, eventlist: UnsafeMutablePointer<kevent>?, nevents: CInt, timeout: UnsafePointer<Darwin.timespec>?) throws -> CInt {
        return try call(nonblocking: true) {
            sysKevent(kq, changelist, nchanges, eventlist, nevents, timeout)
        }.result
    }
}

#endif
