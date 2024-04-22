package dev.taras.hamkalo.spring.controller;

import dev.taras.hamkalo.spring.security.authentication.ApiKeyAuthentication;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class DemoController {

  @GetMapping("/")
  public String name(Authentication authentication) {
    if (authentication instanceof Principal apiKeyAuthentication) {
      return "Hello " + apiKeyAuthentication.getName() + " !";
    }

    return "Hello";
  }

}
