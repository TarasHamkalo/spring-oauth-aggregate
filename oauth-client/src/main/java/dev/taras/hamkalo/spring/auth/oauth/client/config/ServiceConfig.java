package dev.taras.hamkalo.spring.auth.oauth.client.config;

import dev.taras.hamkalo.spring.auth.oauth.client.interceptors.Oauth2TokenAuthorizationInterceptor;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ServiceConfig {

  @Bean
  RestTemplate restTemplate(Oauth2TokenAuthorizationInterceptor interceptor) {
    return new RestTemplateBuilder()
      .additionalInterceptors(interceptor)
      .build();
  }

}
