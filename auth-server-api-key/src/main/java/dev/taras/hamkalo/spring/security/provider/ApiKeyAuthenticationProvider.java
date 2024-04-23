package dev.taras.hamkalo.spring.security.provider;

import dev.taras.hamkalo.spring.security.authentication.ApiKeyAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

  @Value("${api.secret.key}")
  String key;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    var apiAuth = (ApiKeyAuthentication) authentication;
    if (key.equals(apiAuth.getKey())) {
      apiAuth.setAuthenticated(true);
      return apiAuth;
    }

    throw new BadCredentialsException("Api key is not valid");
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return ApiKeyAuthentication.class.equals(authentication);
  }
}
