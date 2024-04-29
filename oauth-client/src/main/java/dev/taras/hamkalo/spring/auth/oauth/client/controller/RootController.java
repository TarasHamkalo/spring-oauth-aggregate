package dev.taras.hamkalo.spring.auth.oauth.client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class RootController {

  @GetMapping("/")
  public String root() {
    return "index";
  }

  @GetMapping("code")
  public String code() {
      return "index";
  }
}
