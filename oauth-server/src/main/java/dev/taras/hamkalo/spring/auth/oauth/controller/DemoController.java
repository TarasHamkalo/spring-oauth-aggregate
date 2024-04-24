package dev.taras.hamkalo.spring.auth.oauth.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/demo")
@RestController
public class DemoController {

  @RequestMapping("/authorized")
  public String authorized(@RequestParam(required = false) String code) {
    return code;
  }

}
