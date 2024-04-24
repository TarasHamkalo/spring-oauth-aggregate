package dev.taras.hamkalo.spring.auth.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import dev.taras.hamkalo.spring.auth.oauth.repository.UserRepository;
import dev.taras.hamkalo.spring.auth.oauth.security.service.JpaUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  UserDetailsService userDetailsService(UserRepository userRepository) {
    return new JpaUserDetailsService(userRepository);
  }

  @Bean
  @Order(1)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
      .oidc(Customizer.withDefaults());

    http
      .exceptionHandling(exceptions -> exceptions
        .defaultAuthenticationEntryPointFor(
          new LoginUrlAuthenticationEntryPoint("/oauth2/login"),
          new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ))
      .oauth2ResourceServer(resourceServer -> resourceServer
          .jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain formLoginSecurityFilterChain(HttpSecurity http) throws Exception {
//localhost:8080/oauth2/authorize?response_type=code&client_id=clientId&secret=secretId&scope=openid&redirect_uri=http://127.0.0.1:8080/demo/authorized
//    http://127.0.0.1:8080/demo/authorized?code=xqeERrz5qoKXZl4Y7Ok8BwDXI0Xe76TxtmX0pnfHkJQaibR-7qKPAyf0cz9gLZ1qDKf8--2gQWMhOAYI0UePDjLeIgF3T_Vgsc7D9-zEcinXyxqQHi_9Z7wfIqwydXRY&continue
    return http
      .formLogin(Customizer.withDefaults())
      .authorizeHttpRequests(r -> r
        .anyRequest().authenticated())
      .build();
  }

  @Bean
  RegisteredClientRepository registeredClientRepository() {
    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("clientId")
      .clientSecret("secretId")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUri("http://127.0.0.1:8080/demo/authorized")
      .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .build();

    return new InMemoryRegisteredClientRepository(oidcClient);
  }

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();

    var jwkKeySet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkKeySet);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}

		return keyPair;
	}

  @Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

  @Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
      .tokenEndpoint("/oauth2/token")
      .jwkSetEndpoint("/oauth2/jwks")
//      .tokenIntrospectionEndpoint("/oauth/introspection")
      .build();
	}
//  @Bean
//  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//    return http
//
//      .csrf(csrf -> csrf
//        .ignoringRequestMatchers("/user"))
//      .authorizeHttpRequests(registry -> registry
//        .requestMatchers(HttpMethod.PUT, "/user").permitAll()
//        .anyRequest().authenticated())
//      .build();
//  }
}
