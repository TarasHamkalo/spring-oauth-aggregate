package dev.taras.hamkalo.spring.auth.oauth.resource.server.config;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.config.token.converter.UsernameAuthoritiesJwtTokenConverter;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SecurityConfig {
  @Value("${jwk.set.uri}")
  String jwkSetUri;

  @Value("${cors.allowed.host}")
  String allowedHost;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .cors(cors -> cors
        .configurationSource(corsConfigurationSource()))
      .oauth2ResourceServer(resourceServer -> resourceServer
        .jwt(jwtConfigurer -> jwtConfigurer
          .jwtAuthenticationConverter(converter())
          .jwkSetUri(jwkSetUri)))
      .authorizeHttpRequests(authorizeRequests -> authorizeRequests
        .anyRequest().authenticated())
      .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    var corsConfiguration = new CorsConfiguration();
    corsConfiguration.setAllowedOrigins(List.of(allowedHost));
    corsConfiguration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
    corsConfiguration.setAllowedHeaders(
      List.of(
        "authorization",
        "content-type"
      )
    );

    corsConfiguration.setMaxAge(1700000L);

    corsConfiguration.setAllowCredentials(true);
    var corsConfigurationSource = new UrlBasedCorsConfigurationSource();
    corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

    return corsConfigurationSource;
  }

  @Bean
  UsernameAuthoritiesJwtTokenConverter converter() {
    return new UsernameAuthoritiesJwtTokenConverter();
  }

}
