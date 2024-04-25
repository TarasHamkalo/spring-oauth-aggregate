package dev.taras.hamkalo.spring.auth.oauth.config.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public abstract class KeyGenerator {

  public static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }

    return keyPair;
  }
}
