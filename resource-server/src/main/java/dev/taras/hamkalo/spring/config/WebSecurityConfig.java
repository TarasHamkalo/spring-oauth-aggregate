package dev.taras.hamkalo.spring.config;

import dev.taras.hamkalo.spring.security.filter.ApiKeyFilter;
import dev.taras.hamkalo.spring.security.provider.ApiKeyAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  AuthenticationProvider authenticationProvider() {
    return new ApiKeyAuthenticationProvider();
  }

  @Bean
  AuthenticationManager authenticationManager() {
    return new ProviderManager(authenticationProvider());
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .httpBasic(Customizer.withDefaults())
      .authorizeHttpRequests(registry -> registry
        .anyRequest().authenticated())
      .addFilterAt(new ApiKeyFilter(authenticationManager()), BasicAuthenticationFilter.class)
      .build();
  }

}
