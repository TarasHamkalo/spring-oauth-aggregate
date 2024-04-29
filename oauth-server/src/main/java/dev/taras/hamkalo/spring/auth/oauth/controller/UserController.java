package dev.taras.hamkalo.spring.auth.oauth.controller;

import dev.taras.hamkalo.spring.auth.oauth.enity.User;
import dev.taras.hamkalo.spring.auth.oauth.repository.UserRepository;
import dev.taras.hamkalo.spring.auth.oauth.request.UserCreateRequest;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Optional;

@Controller
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {

  UserRepository userRepository;

  PasswordEncoder passwordEncoder;

  @PostMapping("/user")
  public String createUser(@ModelAttribute UserCreateRequest userCreateRequest) {
    if (userRepository.existsByUsername(userCreateRequest.getUsername())) {
      throw new IllegalArgumentException("User exists");
    }

    userRepository.save(
      User.builder()
        .username(userCreateRequest.getUsername())
        .password(passwordEncoder.encode(userCreateRequest.getUsername()))
        .build()
    );

    return "forward:login";
  }

  @GetMapping("/user/{username}")
  public Optional<User> getUserByUsername(@PathVariable("username") String username) {
    return userRepository.findUserByUsername(username);
  }

}
