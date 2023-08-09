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

package org.akdilsiz;


import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.Arrays;

public class AESCtrHMAC {
  private int BufferSize = 16 * 1024;
  private int IvSize = 16;
  private byte V1 = 0x1;

  private int hmacSize = 64;

  private SecureRandom secureRandom = new SecureRandom();

  public Throwable Encrypt(String in, String out, byte[] keyAES, byte[] keyHMAC)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, ShortBufferException {
    File outFile = new File(out);
    FileChannel wChannel = new FileOutputStream(outFile, false).getChannel();
    byte[] iv = new byte[this.IvSize];
    byte[] nonce = new byte[96 / 8];
    this.secureRandom.nextBytes(nonce);
    System.arraycopy(nonce, 0, iv, 0, nonce.length);

    Key aesKeySpec = new SecretKeySpec(keyAES, "AES");
    IvParameterSpec ivKeySpec = new IvParameterSpec(iv);

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivKeySpec);

    Key hmacKeySpec = new SecretKeySpec(keyHMAC, "HmacSHA512");
    Mac mac = Mac.getInstance("HmacSHA512");
    mac.init(hmacKeySpec);


    wChannel.write(ByteBuffer.allocateDirect(V1));
    wChannel.write(ByteBuffer.wrap(iv));
    mac.update(iv);

    try (SeekableByteChannel ch = java.nio.file.Files.newByteChannel(Paths.get(in), StandardOpenOption.READ)) {
      ByteBuffer bf = ByteBuffer.allocate(this.BufferSize);
      while (true) {
        int i = ch.read(bf);
        if (i <= 0) {
          break;
        }
        bf.flip();
        ByteBuffer encryptedBF = ByteBuffer.allocate(i);

        cipher.update(bf, encryptedBF);
        bf.clear();
        mac.update(encryptedBF.array());
        i = wChannel.write(ByteBuffer.wrap(encryptedBF.array()));
        if (i == 0) {
          throw new EOFException("not write");
        }
        encryptedBF.clear();
      }
    }
    byte[] mm = mac.doFinal();
    wChannel.write(ByteBuffer.wrap(mm));
    wChannel.close();

    return null;
  }

  public Throwable Decrypt(String in, String out, byte[] keyAES, byte[] keyHMAC)
      throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
    File outFile = new File(out);
    FileChannel wChannel = new FileOutputStream(outFile, false).getChannel();

    try (SeekableByteChannel ch = java.nio.file.Files.newByteChannel(Paths.get(in), StandardOpenOption.READ)) {
      long offset = 0L;
      ByteBuffer version = ByteBuffer.allocate(1);
      int i = ch.read(version);
      if (i == 0) {
        wChannel.close();
        throw new IllegalArgumentException("Version does not exists");
      }
      version.clear();
      offset += 1;

      ByteBuffer iv = ByteBuffer.allocate(this.IvSize);
      i = ch.read(iv);
      if (i == 0) {
        wChannel.close();
        throw new IllegalArgumentException("IV does not exists");
      }

      offset += this.IvSize;

      Key aesKeySpec = new SecretKeySpec(keyAES, "AES");
      IvParameterSpec ivKeySpec = new IvParameterSpec(iv.array());
      iv.clear();

      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivKeySpec);

      Key hmacKeySpec = new SecretKeySpec(keyHMAC, "HmacSHA512");
      Mac mac = Mac.getInstance("HmacSHA512");
      mac.init(hmacKeySpec);

      mac.update(iv);

      byte[] macValue = new byte[this.hmacSize];

      ByteBuffer bf = ByteBuffer.allocate(this.BufferSize);
      while (true) {
        i = ch.read(bf);
        if (i <= 0) break;
        int limit = i;
        if (ch.size() < this.BufferSize || offset+this.BufferSize > ch.size()) {
          limit = i-this.hmacSize;
        }
        bf.flip();
        byte[] buf = new byte[limit];
        bf.get(buf);
        mac.update(buf);
        byte[] decrypted = cipher.update(buf);
        i = wChannel.write(ByteBuffer.wrap(decrypted));
        if (i == 0) {
          wChannel.close();
          throw new EOFException("not write");
        }
        offset += bf.limit();

        if (offset == ch.size()) {
          if (bf.limit() < this.hmacSize) {
            wChannel.close();
            throw new EOFException("enough left");
          }

          for (int j = 0; j < this.hmacSize; j++) {
            macValue[j] = bf.get(bf.limit()-this.hmacSize+j);
          }
          if (bf.limit()-this.hmacSize == this.hmacSize) {
            bf.clear();
            break;
          }
        }

        bf.clear();
      }
      wChannel.close();
      byte[] mm = mac.doFinal();
      if (!Util.bytesToHex(mm).equals(Util.bytesToHex(macValue))) {
        throw new IOException("invalid hmac");
      }

    }

    return null;
  }
}
