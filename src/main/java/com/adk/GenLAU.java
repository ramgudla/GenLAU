package com.adk;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class GenLAU {

  private static final String HMAC_SHA256 = "HmacSHA256";

  private static final String GENERATED_EXT = ".generated";

  private static final String LAU_EXT = ".lau";

  private static final int XMLV2_PDU_START = 0x1f;

  private static final int XMLV2_SIG_OFFSET = 7;

  private static final int XMLV2_ENCODED_SIG_LEN = 24;

  private static final int XMLV2_PRELUDE_LEN = 31;

  private static final int XMLV2_SIG_LEN = 16;

  private static final int BYTE_BUFFER_SIZE = 10000;

  private static final int LAU_KEY_MIN_CHARS = 17;

  private static final int LAU_KEY_MAX_CHARS = 32;

  private boolean mXmlV2;

  private boolean mDigest;

  private boolean mValidate;

  private SecretKeySpec mKey;

  private String[] mFiles;

  public void run(String[] pArgs) throws Exception {
    for (int i = 0; i < pArgs.length; i++) {
      if ("-digest".equals(pArgs[i])) {
        mDigest = true;
      } else if ("-validate".equals(pArgs[i])) {
        mValidate = true;
      } else if ("-xmlv2".equals(pArgs[i])) {
        mXmlV2 = true;
      } else if ("-key".equals(pArgs[i])) {
        mKey = getKey(pArgs[++i]);
      } else if ("-keyfile".equals(pArgs[i])) {
        mKey = getKeyFromFile(pArgs[++i]);
      } else {
        // out of named args, rest are files
        mFiles = Arrays.copyOfRange(pArgs, i, pArgs.length);
        break;
      }
    }

    if (mDigest && mXmlV2) {
      System.out.println("-digest and -xmlv2 options cannot be specified together");
      usage();
    }

    if (!mDigest && (mKey == null)) {
      System.out.println("-key or -keyfile option must be specified to sign or validate");
      usage();
    }

    if (mDigest) {
      digest();
    } else if (mValidate) {
      if (!mXmlV2 && mFiles.length != 2) {
        System.out.println("-validate option without -xmlv2 requires exactly two files");
        usage();
      }
      validate();
    } else {
      sign();
    }
  }

  // useful for unit test
  void setKey(SecretKeySpec pKey) {
    mKey = pKey;
  }

  @SuppressFBWarnings(value = "DM_EXIT", justification = "Exit on incorrect usage is OK for a utility here")
  SecretKeySpec getKey(String pEncodedKey) throws Exception {
    final byte[] key = new byte[LAU_KEY_MAX_CHARS];
    if (pEncodedKey.length() > LAU_KEY_MAX_CHARS || pEncodedKey.length() < LAU_KEY_MIN_CHARS) {
      System.out.println(String.format("LAU key must be between %d and %d characters in length", LAU_KEY_MIN_CHARS, LAU_KEY_MAX_CHARS));
      System.exit(-1);
    } else {
      Arrays.fill(key, (byte) 0);
      System.arraycopy(pEncodedKey.getBytes(StandardCharsets.UTF_8), 0, key, 0, pEncodedKey.getBytes(StandardCharsets.UTF_8).length);
    }
    return new SecretKeySpec(key, HMAC_SHA256);
  }

  @SuppressFBWarnings(value = "DM_EXIT", justification = "Exit on incorrect usage is OK for a utility here")
  SecretKeySpec getKeyFromFile(String pKeyFile) throws Exception {
    try (FileInputStream in = new FileInputStream(pKeyFile)) {
      final byte[] keyBytes = IOUtils.toByteArray(in);

      System.out.println("keyBytes length: " + keyBytes.length);

      final byte[] key = new byte[LAU_KEY_MAX_CHARS];
      if (keyBytes.length > LAU_KEY_MAX_CHARS || keyBytes.length < LAU_KEY_MIN_CHARS) {
        System.out.println(String.format("LAU key must be between %d and %d characters in length", LAU_KEY_MIN_CHARS, LAU_KEY_MAX_CHARS));
        System.exit(-1);
      } else {
        Arrays.fill(key, (byte) 0);
        System.arraycopy(keyBytes, 0, key, 0, keyBytes.length);
      }
      return new SecretKeySpec(key, HMAC_SHA256);
    }
  }

  // displays a SHA256 digest for every named file on the command line
  protected void digest() throws Exception {
    for (String s : mFiles) {
      try (InputStream in = new FileInputStream(s)) {
        final byte[] hash = DigestUtils.sha256(in);
        System.out.println("Base64 SHA-256 for " + s + ": " + Base64.encodeBase64String(hash));
      }
    }
  }

  // validates the LAU for a file
  protected void validate() throws Exception {
    if (mXmlV2) {
      validateXmlv2();
    } else {
      validateNormalFile();
    }

  }

  // validation of normal file (e.g. RJE) just compares HMAC 256 calculated over content bytestream
  @SuppressFBWarnings(value = "DM_EXIT", justification = "Exit on incorrect usage is OK here")
  protected void validateNormalFile() throws Exception {
    final Mac mac = Mac.getInstance(HMAC_SHA256);
    mac.init(mKey);
    final byte[] expected;
    try (InputStream in = new FileInputStream(mFiles[0])) {
      expected = Base64.encodeBase64(sign(in));
    }
    try (InputStream in = new FileInputStream(mFiles[1])) {
      final byte[] given = IOUtils.toByteArray(in);
      if (Arrays.equals(expected, given)) {
        System.out.println("LAU is correct");
      } else {
        System.out.println("LAU is incorrect. Expected: " + expected);
        System.exit(1);
      }
    }
  }

  // validation of XmlV2 files
  @SuppressFBWarnings(value = "DM_EXIT", justification = "Exit on incorrect usage is OK here")
  protected void validateXmlv2() throws Exception {
    for (String s : mFiles) {
      try (InputStream in = new FileInputStream(s)) {
        final byte[] content = IOUtils.toByteArray(in);
        final byte[] signed = signXmlV2(content);
        if (!Arrays.equals(content, signed)) {
          System.out.println("LAU for " + s + " is incorrect");
          System.exit(1);
        } else {
          System.out.println("LAU for " + s + " is correct");
        }
      }
    }
  }

  // sign the required files (generate either '.lau' for regular file or '.generated' copy for Xmlv2)
  protected void sign() throws Exception {
    for (String s : mFiles) {
      final Mac mac = Mac.getInstance(HMAC_SHA256);
      mac.init(mKey);
      try (InputStream in = new FileInputStream(s)) {
        if (mXmlV2) {
          final byte[] content = IOUtils.toByteArray(in);
          if (content[0] == 0x1f) {
            processXmlV2File(content, s);
          } else {
            System.out.println("Files must start 0x1F if option '-xmlv2' is specified");
          }
        } else {
          processRegularFile(in, s);
        }
      }
    }
  }

  private void processXmlV2File(byte[] pContent, String pFileName) throws GeneralSecurityException, IOException {
    try (FileOutputStream out = new FileOutputStream(pFileName + GENERATED_EXT)) {
      out.write(signXmlV2(pContent));
    }
  }

  private byte[] signXmlV2(byte[] pContent) throws GeneralSecurityException {
    final byte[] signedContent = Arrays.copyOf(pContent, pContent.length);
    int start = 0;
    int end = 0;
    do {
      end = findPduEnd(signedContent, start);
      final byte[] signableContent = Arrays.copyOfRange(signedContent, start + XMLV2_PRELUDE_LEN, end);
      final byte[] sig = sign(signableContent);
      // XMLv2 signatures are truncated in the PDU.
      final byte[] truncated = Base64.encodeBase64(Arrays.copyOf(sig, XMLV2_SIG_LEN));

      for (int i = start; i < XMLV2_ENCODED_SIG_LEN; i++) {
        signedContent[i + XMLV2_SIG_OFFSET] = truncated[i];
      }
      start = end;
    } while (end < signedContent.length);

    return signedContent;
  }

  private int findPduEnd(byte[] pContent, int pStartFrom) {
    for (int i = pStartFrom + 1; i < pContent.length; i++) {
      if (pContent[i] == (byte) XMLV2_PDU_START) {
        return i;
      }
    }
    return pContent.length;
  }

  private void processRegularFile(InputStream pContent, String pFileName) throws GeneralSecurityException, IOException {
    try (FileOutputStream out = new FileOutputStream(pFileName + LAU_EXT)) {
      out.write(Base64.encodeBase64(sign(pContent)));
    }
  }

  // in memory version
  byte[] sign(byte[] pContent) throws GeneralSecurityException {
    final Mac mac = Mac.getInstance(HMAC_SHA256);
    mac.init(mKey);
    return mac.doFinal(pContent);
  }

  // uses an underlying buffer for large amounts of data
  byte[] sign(InputStream pContent) throws GeneralSecurityException, IOException {
    final Mac mac = Mac.getInstance(HMAC_SHA256);
    mac.init(mKey);
    final byte[] buffer = new byte[BYTE_BUFFER_SIZE];
    int len = pContent.read(buffer);
    while (len > 0) {
      mac.update(buffer, 0, len);
      len = pContent.read(buffer);
    }
    return mac.doFinal();
  }

  //CHECKSTYLE:OFF main app
  public static void main(String[] pArgs) {
    //CHECKSTYLE:OFF
    if (pArgs.length < 2) {
      usage();
    } else {
      try {
        new GenLAU().run(pArgs);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  @SuppressFBWarnings(value = "DM_EXIT", justification = "Exit on incorrect usage is OK here")
  protected static void usage() {
    System.out.println("Usage: java -jar genLAU.jar [-xmlv2] -key <key> <file 1> ... <file N>");
    System.out.println("       java -jar genLAU.jar [-xmlv2] -keyfile <keyfile> <file 1> ... <file N>");
    System.out.println("       java -jar genLAU.jar -digest <file 1> ... <file N>");
    System.out.println("       java -jar genLAU.jar -validate -key <key> <file> <LAU file>");
    System.out.println("       java -jar genLAU.jar -validate -xmlv2 -key <key> <file 1> ... <file N>");
    System.exit(-1);
  }
}

