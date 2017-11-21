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
///
/// LinuxMain.swift
///
import XCTest

///
/// NOTE: This file was generated by generate_linux_tests.rb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

#if os(Linux) || os(FreeBSD)
   @testable import NIOConcurrencyHelpersTests
   @testable import NIOHTTP1Tests
   @testable import NIOOpenSSLTests
   @testable import NIOTLSTests
   @testable import NIOTests

   XCTMain([
         testCase(AdaptiveRecvByteBufferAllocatorTest.allTests),
         testCase(ApplicationProtocolNegotiationHandlerTests.allTests),
         testCase(BaseObjectTest.allTests),
         testCase(ByteBufferTest.allTests),
         testCase(ByteToMessageDecoderTest.allTests),
         testCase(ChannelPipelineTest.allTests),
         testCase(ChannelTests.allTests),
         testCase(CircularBufferTests.allTests),
         testCase(ClientSNITests.allTests),
         testCase(EchoServerClientTest.allTests),
         testCase(EmbeddedChannelTest.allTests),
         testCase(EventLoopFutureTest.allTests),
         testCase(EventLoopTest.allTests),
         testCase(FileRegionTest.allTests),
         testCase(HTTPHeadersTest.allTests),
         testCase(HTTPRequestEncoderTests.allTests),
         testCase(HTTPResponseEncoderTests.allTests),
         testCase(HTTPServerClientTest.allTests),
         testCase(HTTPTest.allTests),
         testCase(HTTPUpgradeTestCase.allTests),
         testCase(IdentityVerificationTest.allTests),
         testCase(IdleStateHandlerTest.allTests),
         testCase(MarkedCircularBufferTests.allTests),
         testCase(MessageToByteEncoderTest.allTests),
         testCase(OpenSSLALPNTest.allTests),
         testCase(OpenSSLIntegrationTest.allTests),
         testCase(SSLCertificateTest.allTests),
         testCase(SSLPrivateKeyTest.allTests),
         testCase(SniHandlerTest.allTests),
         testCase(SocketAddressTest.allTests),
         testCase(NIOConcurrencyHelpersTests.allTests),
         testCase(SystemTest.allTests),
         testCase(TLSConfigurationTest.allTests),
         testCase(TypeAssistedChannelHandlerTest.allTests),
    ])
#endif