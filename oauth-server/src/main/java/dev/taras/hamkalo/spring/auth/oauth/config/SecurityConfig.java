package dev.taras.hamkalo.spring.auth.oauth.config;


import dev.taras.hamkalo.spring.auth.oauth.config.customizer.UserInfoMapper;
import dev.taras.hamkalo.spring.auth.oauth.repository.UserRepository;
import dev.taras.hamkalo.spring.auth.oauth.security.service.JpaUserDetailsService;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.function.Function;

/**
 * Almost whole this configuration can be done in properties file
 */
@Configuration
@EnableWebSecurity
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SecurityConfig {

  @Value("${oauth.client.untrusted.host}")
  String clientHost;

  @Bean
  @Order(1)
  SecurityFilterChain oauthEndpointsFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
      .oidc(oidc -> oidc
        .userInfoEndpoint(userInfo -> userInfo
          .userInfoMapper(userInfoMapper())));

    http
      .exceptionHandling(exceptions -> exceptions
        .defaultAuthenticationEntryPointFor(
          new LoginUrlAuthenticationEntryPoint("/login"),
          new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
      .cors(conf -> conf
        .configurationSource(corsConfigurationSource()))
      .oauth2ResourceServer(resourceServer -> resourceServer
        .jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    return http
      .cors(conf -> conf
        .configurationSource(corsConfigurationSource()))
      .authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/login").permitAll()
        .requestMatchers("/js/**").permitAll()
        .requestMatchers("/css/**").permitAll()
        .requestMatchers("/user").permitAll()
        .anyRequest().authenticated())
      .formLogin(configurer -> configurer
        .loginPage("/login"))
      .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    var corsConfiguration = new CorsConfiguration();
    corsConfiguration.setAllowedOrigins(List.of(clientHost));
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
  Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
    return new UserInfoMapper();
  }

  @Bean
  AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  UserDetailsService userDetailsService(UserRepository userRepository) {
    return new JpaUserDetailsService(userRepository);
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

}
