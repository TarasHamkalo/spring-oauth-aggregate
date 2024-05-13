package dev.taras.hamkalo.spring.auth.oauth.config.customizer;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class Oauth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

  String managerScopeName;

  @Override
  public void customize(JwtEncodingContext context) {
    var clientScopes = context.getRegisteredClient().getScopes();
    if (clientScopes.contains(managerScopeName)) {
      customizeManagerToken(context);
    } else {
      customizeUserToken(context);
    }

  }

  private void customizeManagerToken(JwtEncodingContext context) {
    context.getClaims().claim("authorities", List.of("ROLE_" + managerScopeName));
  }

  private void customizeUserToken(JwtEncodingContext context) {
    var authorities = context.getPrincipal().getAuthorities().stream()
      .map(GrantedAuthority::getAuthority)
      .toList();

    context.getClaims().claim("username", context.getPrincipal().getName());
    context.getClaims().claim("authorities", authorities);
  }

}
