// Copyright 2023 Abdulkadir Dilsiz <akdilsiz@tecpor.com>
// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import org.akdilsiz.AESCtrHMAC;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class AESCtrHMACTest {
  @Test
  void Encrypt() throws IOException {
    SecureRandom sc = new SecureRandom();
    SecureRandom sc2 = new SecureRandom();
    byte[] keyAES = new byte[32];
    byte[] keyHMAC = new byte[32];
    byte[] nonce1 = new byte[64];
    sc.nextBytes(nonce1);
    System.arraycopy(nonce1, 0, keyAES, 0, 32);
    byte[] nonce2 = new byte[64];
    sc.nextBytes(nonce2);
    System.arraycopy(nonce2, 0, keyHMAC, 0, 32);

    sc.nextBytes(keyAES);
    sc2.nextBytes(keyHMAC);

    String a1 = "ZmBvVJo2kKc5rSWcC9qAHIyyYJRRwiC3";
    String a3 = "n8MYP53vdNkG0uYaWreDOVTjkaI4JQL3";
    String testFile = Paths.get(System.getProperty("user.dir"), "src", "test", "files", "efetherock.jpg").toString();
    Path testOuterFile = Paths.get(System.getProperty("user.dir"), "src", "efetherock.encrypt");

    Files.deleteIfExists(testOuterFile);

    AESCtrHMAC enc = new AESCtrHMAC();

    Assertions.assertDoesNotThrow(() -> {
      enc.Encrypt(testFile, testOuterFile.toString(), a1.getBytes(), a3.getBytes());
    });
  }

  @Test
  void Decrypt() throws IOException {
    SecureRandom sc = new SecureRandom();
    SecureRandom sc2 = new SecureRandom();
    byte[] keyAES = new byte[32];
    byte[] keyHMAC = new byte[32];
    byte[] nonce1 = new byte[64];
    sc.nextBytes(nonce1);
    System.arraycopy(nonce1, 0, keyAES, 0, 32);
    byte[] nonce2 = new byte[64];
    sc.nextBytes(nonce2);
    System.arraycopy(nonce2, 0, keyHMAC, 0, 32);

    sc.nextBytes(keyAES);
    sc2.nextBytes(keyHMAC);

    String a1 = "ZmBvVJo2kKc5rSWcC9qAHIyyYJRRwiC6";
    String a3 = "n8MYP53vdNkG0uYaWreDOVTjkaI4JQL8";
    String testFile = Paths.get(System.getProperty("user.dir"), "src", "test", "files", "efetherock.jpg").toString();
    Path testEncryptedOuterFile = Paths.get(System.getProperty("user.dir"), "src", "efetherock2.encrypt");
    Path testDecryptedOuterFile = Paths.get(System.getProperty("user.dir"), "src", "efetherock2.jpg");

    Files.deleteIfExists(testEncryptedOuterFile);
    Files.deleteIfExists(testDecryptedOuterFile);

    AESCtrHMAC enc = new AESCtrHMAC();

    Assertions.assertDoesNotThrow(() -> {
      enc.Encrypt(testFile, testEncryptedOuterFile.toString(), a1.getBytes(), a3.getBytes());
    });

    Assertions.assertDoesNotThrow(() -> {
      enc.Decrypt(testEncryptedOuterFile.toString(), testDecryptedOuterFile.toString(), a1.getBytes(), a3.getBytes());
    });

  }
}
