package dev.taras.hamkalo.spring.auth.oauth.client.interceptors;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class Oauth2TokenAuthorizationInterceptor implements ClientHttpRequestInterceptor {

  OAuth2AuthorizedClientManager authorizedClientManager;

  ClientRegistration clientRegistration;

  @Override
  public ClientHttpResponse intercept(
    HttpRequest request,
    byte[] body,
    ClientHttpRequestExecution execution) throws IOException {


    var authorizationRequest = OAuth2AuthorizeRequest
      .withClientRegistrationId(clientRegistration.getRegistrationId())
      .principal(clientRegistration.getClientName())
      .build();

    var authorizedClient = authorizedClientManager.authorize(authorizationRequest);
    if (authorizedClient == null) {
      throw new IllegalAccessError("Client credentials authorization not supported");
    }

    var token = authorizedClient.getAccessToken().getTokenValue();

    request.getHeaders().setBearerAuth(token);
    return execution.execute(request, body);
  }

}
