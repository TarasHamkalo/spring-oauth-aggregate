package dev.taras.hamkalo.spring.auth.oauth.resource.server.config.token.converter;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.config.token.authentication.UsernameJwtAuthenticationToken;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class UsernameAuthoritiesJwtTokenConverter
  implements Converter<Jwt, UsernameJwtAuthenticationToken> {

  @Override
  public UsernameJwtAuthenticationToken convert(Jwt source) {
    var authorities = source.getClaimAsStringList("authorities").stream()
      .map(SimpleGrantedAuthority::new)
      .toList();

    return UsernameJwtAuthenticationToken.builder()
      .username(source.getClaim("username"))
      .authorities(authorities)
      .jwt(source)
      .build();
  }
}
