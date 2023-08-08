package org.akdilsiz;


import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.util.Arrays;

public class AESCtrHMAC {
  private Integer BufferSize = 16 * 1024;
  private Integer IvSize = 16;
  private Byte V1 = 0x1;

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
        int iii = wChannel.write(ByteBuffer.wrap(encryptedBF.array()));
        System.out.println(iii);
        encryptedBF.clear();
      }
    }
    wChannel.write(ByteBuffer.wrap(mac.doFinal()));
    wChannel.close();

    return null;
  }

  public Throwable Decrypt(String in, String out, byte[] keyAES, byte[] keyHMAC)
      throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
    File outFile = new File(out);
    FileChannel wChannel = new FileOutputStream(outFile, false).getChannel();

    try (SeekableByteChannel ch = java.nio.file.Files.newByteChannel(Paths.get(in), StandardOpenOption.READ)) {
      ByteBuffer version = ByteBuffer.allocate(1);
      int i = ch.read(version);
      if (i == 0) {
        throw new IOException("Version does not exists");
      }

      ByteBuffer iv = ByteBuffer.allocate(this.IvSize);
      i = ch.read(iv);
      if (i == 0) {
        throw new IOException("IV does not exists");
      }

      Key aesKeySpec = new SecretKeySpec(keyAES, "AES");
      IvParameterSpec ivKeySpec = new IvParameterSpec(iv.array());

      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivKeySpec);

      Key hmacKeySpec = new SecretKeySpec(keyHMAC, "HmacSHA512");
      Mac mac = Mac.getInstance("HmacSHA512");
      mac.init(hmacKeySpec);

      mac.update(iv);


    }

    return null;
  }
}
