package org.postgresql.jdbc;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

public class EncoderHelper {

  public byte[] base64Encode(byte[] dataToEncode) {
    if (dataToEncode == null) {
      throw new IllegalArgumentException(
        "EncoderHelper.base64Encode(): 'dataToEncode' must be provided");
    }
    return getEncoder().encode(dataToEncode);
  }

  public byte[] base64Decode(byte[] encodedData) {
    if (encodedData == null || encodedData.length == 0) {
      throw new IllegalArgumentException(
        "EncoderHelper.base64Encode(): 'encodedData' must be provided");
    }
    return getDecoder().decode(encodedData);
  }
}
