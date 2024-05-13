package dev.taras.hamkalo.spring.auth.oauth.client.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
      .authorizeHttpRequests(authorize -> authorize
        .anyRequest().permitAll())
      .csrf(AbstractHttpConfigurer::disable)
      .build();
  }

  @Bean
  OAuth2AuthorizedClientManager authorizedClientManager(
    ClientRegistrationRepository clientRegistrationRepository,
    OAuth2AuthorizedClientService authorizedClientService) {

    var authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
      .clientCredentials()
      .build();

    var authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
      clientRegistrationRepository, authorizedClientService
    );

    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
  }

  @Bean
  ClientRegistrationRepository clientRegistrationRepository(
    ClientRegistration... clientRegistration) {
    return new InMemoryClientRegistrationRepository(clientRegistration);
  }

  @Bean
  ClientRegistration clientRegistration(
    @Value("${oauth.token.issuer.uri}") String issuer,
    @Value("${oauth.client.trusted.id}") String clientId,
    @Value("${oauth.client.trusted.secret}") String clientSecret,
    @Value("${oauth.manager.scope.name}") String managerScope) {

    return ClientRegistrations.fromIssuerLocation(issuer)
      .registrationId(clientId)
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .clientSecret(clientSecret)
      .clientId(clientId)
      .scope(managerScope)
      .build();
  }

  @Bean
  JwtDecoder jwtDecoder(@Value("${oauth.token.issuer.uri}") String issuer) {
    return JwtDecoders.fromIssuerLocation(issuer);
  }

}
