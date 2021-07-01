package org.postgresql.jdbc;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.HashMap;
import java.util.Map;

public class EncryptorService {

  private static final String SEPARATOR = "|";

  private final CryptoHelper crypto = new CryptoHelper();
  private final EncoderHelper encoder = new EncoderHelper();
  private final String primaryKeyId;
  private final String primaryKeyPassword;
  private final Map<String, String> keyMap;

  public EncryptorService(
    String primaryKeyId, String primaryKeyPassword, String secondaryKeyId, String secondaryKeyPassword
  ) {
    this.primaryKeyId = primaryKeyId;
    this.primaryKeyPassword = primaryKeyPassword;

    this.keyMap = new HashMap<>();
    keyMap.put(primaryKeyId, primaryKeyPassword);

    if (!isEmpty(secondaryKeyId) && !secondaryKeyId.equalsIgnoreCase(primaryKeyId) && !isEmpty(secondaryKeyPassword)) {
      keyMap.put(secondaryKeyId, secondaryKeyPassword);
    }
  }

  private boolean isEmpty(String value) {
    return value == null || value.isEmpty();
  }

  public String encrypt(String value) {
    try {
      byte[] encryptedValue = crypto.encrypt(value.getBytes(UTF_8), primaryKeyPassword);
      String encodedValue = new String(encoder.base64Encode(encryptedValue), UTF_8);
      return primaryKeyId + SEPARATOR + encodedValue;
    } catch (Exception ex) {
      throw new RuntimeException("Cannot encrypt value", ex);
    }
  }

  public String decrypt(String encryptedValue) {
    int separatorIndex = encryptedValue.indexOf(SEPARATOR);
    if (separatorIndex == -1) {
      throw new IllegalStateException("EncryptorService.decrypt(): value seems to be unencrypted = '" + encryptedValue + "'");
    }
    String keyId = encryptedValue.substring(0, separatorIndex);
    if (!keyMap.containsKey(keyId)) {
      throw new IllegalStateException("EncryptorService.decrypt(): unknown encryption key identifier = '" + keyId + "'");
    }

    try {
      String password = keyMap.get(keyId);
      String actualValue = encryptedValue.substring(separatorIndex + 1);
      byte[] decodedValue = encoder.base64Decode(actualValue.getBytes(UTF_8));
      byte[] decryptedValue = crypto.decrypt(decodedValue, password);
      return new String(decryptedValue);
    } catch (Exception ex) {
      throw new RuntimeException("Cannot decrypt value", ex);
    }
  }
}
