package dev.taras.hamkalo.spring.auth.oauth.config;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ClientsConfig {

  PasswordEncoder passwordEncoder;

  @Bean
  RegisteredClientRepository registeredClientRepository(RegisteredClient... clients) {
    return new InMemoryRegisteredClientRepository(clients);
  }

  @Bean
  RegisteredClient untrustedClient(
    @Value("${oauth.client.untrusted.id}") String clientId,
    @Value("${oauth.client.untrusted.secret}") String clientSecret,
    @Value("${oauth.client.untrusted.uri}") String clientRedirect) {

    return RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(clientId)
      .clientSecret(passwordEncoder.encode(clientSecret))
      .redirectUri(clientRedirect)
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .clientSettings(ClientSettings.builder()
        .requireProofKey(false)
        .requireAuthorizationConsent(true).build())
      .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(5))
        .reuseRefreshTokens(false)
        .build())
      .build();
  }

  @Bean
  RegisteredClient trustedClient(
    @Value("${oauth.client.trusted.id}") String clientId,
    @Value("${oauth.client.trusted.secret}") String clientSecret,
    @Value("${oauth.manager.scope.name}") String managerScope) {

    return RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(clientId)
      .clientSecret(passwordEncoder.encode(clientSecret))
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .scope(managerScope)
      .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(5))
        .build())
      .build();
  }

}
