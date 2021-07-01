package org.postgresql.jdbc;

import static java.nio.ByteBuffer.allocate;
import static java.nio.ByteBuffer.wrap;
import static java.security.SecureRandom.getInstanceStrong;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoHelper {

  // https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
  private static final String ENCRYPTION_ALGORITHM = "AES";
  // https://en.wikipedia.org/wiki/Galois/Counter_Mode
  private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
  // https://tools.ietf.org/html/rfc8018
  private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  // https://en.wikipedia.org/wiki/Authenticated_encryption
  // authentication tag – 128 bits (16 bytes)
  private static final int TAG_LENGTH_BIT = 128;
  // https://en.wikipedia.org/wiki/Initialization_vector
  // AES-GCM needs IV 96-bit (12 bytes)
  private static final int IV_LENGTH_BYTE = 12;
  // https://en.wikipedia.org/wiki/Salt_(cryptography)
  private static final int SALT_LENGTH_BYTE = 16;
  // AES key size - 256 bits
  private static final int KEY_SIZE_BIT = 256;
  // https://en.wikipedia.org/wiki/Rainbow_table
  // number of times password is hashed when deriving a symmetric key, more iterations higher cost of producing keys, hence slows down the attacks
  private static final int ITERATION_COUNT = 65_536;

  /**
   * @param byteArr  array of bytes to encrypt
   * @param password used to create a secret
   * @return byteArr encrypted with AES 256 bit password derived key
   * @throws Exception in case encryption fails
   */
  public byte[] encrypt(byte[] byteArr, String password) throws Exception {
    byte[] iv = getRandomByteArr(IV_LENGTH_BYTE);
    byte[] salt = getRandomByteArr(SALT_LENGTH_BYTE);
    Key secret = getKey(password, salt);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    byte[] cipherText = cipher.doFinal(byteArr);
    return allocate(iv.length + salt.length + cipherText.length)
      .put(iv)
      .put(salt)
      .put(cipherText)
      .array();
  }

  public byte[] decrypt(byte[] byteArr, String password) throws Exception {
    ByteBuffer bb = wrap(byteArr);
    byte[] iv = new byte[IV_LENGTH_BYTE];
    bb.get(iv);
    byte[] salt = new byte[SALT_LENGTH_BYTE];
    bb.get(salt);
    byte[] cipherText = new byte[bb.remaining()];
    bb.get(cipherText);
    Key secret = getKey(password, salt);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    return cipher.doFinal(cipherText);
  }

  /**
   * @param byteArr array of bytes to encrypt
   * @param secret  used for encryption
   * @return byteArr encrypted with
   * @throws Exception in case encryption fails
   */
  private byte[] encrypt(byte[] byteArr, Key secret) throws Exception {
    byte[] iv = getRandomByteArr(IV_LENGTH_BYTE);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    byte[] cipherText = cipher.doFinal(byteArr);
    return allocate(iv.length + cipherText.length)
      .put(iv)
      .put(cipherText)
      .array();
  }

  private byte[] decrypt(byte[] byteArr, Key secret) throws Exception {
    ByteBuffer bb = wrap(byteArr);
    byte[] iv = new byte[IV_LENGTH_BYTE];
    bb.get(iv);
    byte[] cipherText = new byte[bb.remaining()];
    bb.get(cipherText);
    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    cipher.init(DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    return cipher.doFinal(cipherText);
  }

  public Key getKey() throws Exception {
    KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
    keyGen.init(KEY_SIZE_BIT, getInstanceStrong());
    return keyGen.generateKey();
  }

  /**
   * @param password used to derive the key
   * @param salt     random salt
   * @return password derived AES 256-bit key
   * @throws Exception
   */
  public Key getKey(String password, byte[] salt) throws Exception {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE_BIT);
    return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ENCRYPTION_ALGORITHM);
  }

  /**
   * @param length
   * @return random bytes array
   */
  private byte[] getRandomByteArr(int length) {
    byte[] byteArr = new byte[length];
    new SecureRandom().nextBytes(byteArr);
    return byteArr;
  }

}
