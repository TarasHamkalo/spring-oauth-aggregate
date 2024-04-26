package dev.taras.hamkalo.spring.auth.key.config;

import dev.taras.hamkalo.spring.auth.key.repository.UserRepository;
import dev.taras.hamkalo.spring.auth.key.security.JpaUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  UserDetailsService userDetailsService(UserRepository userRepository) {
    return new JpaUserDetailsService(userRepository);
  }

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
      .httpBasic(Customizer.withDefaults())
      .csrf(csrf -> csrf
        .ignoringRequestMatchers("/user"))
      .authorizeHttpRequests(registry -> registry
        .requestMatchers(HttpMethod.PUT, "/user").permitAll()
        .anyRequest().authenticated())
      .build();
  }

}

//  @Bean
//  AuthenticationProvider authenticationProvider() {
//    return new ApiKeyAuthenticationProvider();
//  }

//  @Bean
//  AuthenticationManager authenticationManager() {
//    return http.getSharedObject(AuthenticationManager.class);
//    return new ProviderManager(authenticationProvider());
//  }

