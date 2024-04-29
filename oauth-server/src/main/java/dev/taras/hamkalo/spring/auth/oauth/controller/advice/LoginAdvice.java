package dev.taras.hamkalo.spring.auth.oauth.controller.advice;

import dev.taras.hamkalo.spring.auth.oauth.request.UserCreateRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@Component
@ControllerAdvice
public class LoginAdvice {

  @ModelAttribute("signupForm")
  public UserCreateRequest userCreateRequest() {
    return new UserCreateRequest();
  }

}
