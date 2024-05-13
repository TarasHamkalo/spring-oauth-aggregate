package dev.taras.hamkalo.spring.auth.oauth.client.controller;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestTemplate;

@Controller
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class HomeController {

  @Value("${resource.server.api.uri}")
  String url;

  RestTemplate restTemplate;

  @NonFinal
  String response = "No response from server";

  @GetMapping("/")
  public String index(Model model) {
    model.addAttribute("authenticatedRequestResult", response);
    return "index";
  }

  @PostMapping("/authentication-required")
  public String makeAuthenticatedRequest() {
    this.response = restTemplate.getForObject(url + "/private", String.class);
    return "redirect:/";
  }

}