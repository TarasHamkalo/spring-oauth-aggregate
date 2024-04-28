package dev.taras.hamkalo.spring.auth.oauth.resource.server.controller;

import dev.taras.hamkalo.spring.auth.oauth.resource.server.security.token.authentication.UsernameJwtAuthenticationToken;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {

  @GetMapping("/private")
  public String privateResource(Authentication authentication) {
    if (authentication instanceof UsernameJwtAuthenticationToken jwtToken) {
      var authorities = jwtToken.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();
      return String.format(
        "%s : {%s}", jwtToken.getUsername(), String.join(", ", authorities)
      );

    }

    return authentication.toString();
  }

  @GetMapping("/public")
  public String publicResource(@RequestParam(required = false) String code) {
    return "This is public page, your auth code is " + code;

  }

  @GetMapping("/rate")
  @PreAuthorize("hasAuthority('rate')")
  public String rate() {
    return "You are probably allowed to rate";
  }

  @GetMapping("/smth")
  @PostAuthorize("hasAuthority('could_not_have')")
  public String smth() {
    return "Do smth";
  }

}
