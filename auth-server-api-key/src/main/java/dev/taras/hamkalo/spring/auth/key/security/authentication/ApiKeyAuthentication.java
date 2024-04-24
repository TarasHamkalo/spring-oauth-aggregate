package dev.taras.hamkalo.spring.auth.key.security.authentication;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;


@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ApiKeyAuthentication extends AbstractAuthenticationToken {

  @Getter
  String key;

  public ApiKeyAuthentication(Collection<? extends GrantedAuthority> authorities, String key) {
    super(authorities);
    this.key = key;
  }

  @Override
  public Object getCredentials() {
    return key;
  }

  @Override
  public Object getPrincipal() {
    return null;
  }

}