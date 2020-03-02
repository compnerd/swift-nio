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
#ifndef C_NIO_WINDOWS_H
#define C_NIO_WINDOWS_H

#if defined(_WIN32)

#include <WinSock2.h>

#define NIO(s) CNIOWindows_ ## s

// Windows does not have a `sendmmsg` available.

typedef struct {
  WSAMSG msg_hdr;
  unsigned int msg_len;
} NIO(mmsghdr);

#undef NIO

#endif

#endif
