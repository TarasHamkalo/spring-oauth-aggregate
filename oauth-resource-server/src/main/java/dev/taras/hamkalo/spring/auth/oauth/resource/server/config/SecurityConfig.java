package dev.taras.hamkalo.spring.auth.oauth.resource.server.config;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.security.token.converter.UsernameAuthoritiesJwtTokenConverter;
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
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http

      .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

      .oauth2ResourceServer(resourceServer -> resourceServer
        .jwt(jwtConfigurer -> jwtConfigurer
          .jwtAuthenticationConverter(converter())
          .jwkSetUri("http://localhost:7070/oauth2/jwks")))

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
