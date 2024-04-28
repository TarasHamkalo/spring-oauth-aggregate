package dev.taras.hamkalo.spring.auth.oauth.resource.server.security.token.authentication;

import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.Collections;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UsernameJwtAuthenticationToken extends JwtAuthenticationToken {

  String username;

  public UsernameJwtAuthenticationToken(Jwt jwt, String username) {
    this(jwt, Collections.emptyList(), username);
  }

  @Builder
  public UsernameJwtAuthenticationToken(
    Jwt jwt, Collection<? extends GrantedAuthority> authorities, String username
  ) {
    super(jwt, authorities);
    this.username = username;
  }
}
