package dev.taras.hamkalo.spring.auth.oauth.resource.server.config;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.security.token.converter.UsernameAuthoritiesJwtTokenConverter;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SecurityConfig {

  @Value("${jwk.set.uri}")
  String jwkSetUri;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .oauth2ResourceServer(resourceServer -> resourceServer
        .jwt(jwtConfigurer -> jwtConfigurer
          .jwtAuthenticationConverter(converter())
          .jwkSetUri(jwkSetUri)))
      .authorizeHttpRequests(authorizeRequests -> authorizeRequests
        .requestMatchers("/demo/public").permitAll()
        .anyRequest().authenticated())
      .build();
  }

  @Bean
  UsernameAuthoritiesJwtTokenConverter converter() {
    return new UsernameAuthoritiesJwtTokenConverter();
  }

}
