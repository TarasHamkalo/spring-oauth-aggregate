package dev.taras.hamkalo.spring.auth.oauth.config.customizer;

import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.function.Function;

public class UserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

  @Override
  public OidcUserInfo apply(OidcUserInfoAuthenticationContext context) {
    OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
    if (authentication.getPrincipal() instanceof JwtAuthenticationToken authenticationToken) {
      Jwt token = authenticationToken.getToken();

      return OidcUserInfo.builder()
        .name(token.getClaim("username"))
        .build();
    }

    throw new IllegalArgumentException(
      String.format("Unsupported authentication type: %s", authentication.getClass())
    );
  }

}
