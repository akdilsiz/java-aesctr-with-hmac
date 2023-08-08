import org.akdilsiz.AESCtrHMAC;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

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
//    Path temp = Files.createTempFile("aesctr", ".encrypt");

    Assertions.assertDoesNotThrow(() -> {
      enc.Encrypt(testFile, testOuterFile.toString(), a1.getBytes(), a3.getBytes());
    });

  }
}
