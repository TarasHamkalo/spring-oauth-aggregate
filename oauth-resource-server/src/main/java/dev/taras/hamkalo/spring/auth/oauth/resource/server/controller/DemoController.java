package dev.taras.hamkalo.spring.auth.oauth.resource.server.controller;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.config.token.authentication.UsernameJwtAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;

@RestController
@RequestMapping("/demo")
public class DemoController {

  @GetMapping("/private")
  public String privateResource(Authentication authentication) {
    if (authentication instanceof UsernameJwtAuthenticationToken jwtToken) {
      var authorities = jwtToken.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

      var username = jwtToken.getUsername() == null ? "Unknown User" : jwtToken.getUsername();
      return String.format(
        "[%s] %s : {%s}",
        Timestamp.from(Instant.now()),
        username,
        String.join(", ", authorities)
      );
    }

    return authentication.toString();
  }

}
