package dev.taras.hamkalo.spring.auth.key.controller;

import dev.taras.hamkalo.spring.auth.key.enity.User;
import dev.taras.hamkalo.spring.auth.key.repository.UserRepository;
import dev.taras.hamkalo.spring.auth.key.request.UserCreateRequest;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {

  UserRepository userRepository;

  PasswordEncoder passwordEncoder;

  @PutMapping("/user")
  public void createUser(@RequestBody UserCreateRequest userCreateRequest) {
    if (userRepository.existsByUsername(userCreateRequest.username())) {
      throw new IllegalArgumentException("User exists");
    }

    userRepository.save(
      User.builder()
        .username(userCreateRequest.username())
        .password(passwordEncoder.encode(userCreateRequest.password()))
        .build()
    );
  }

  @GetMapping("/user/{username}")
  public Optional<User> getUserByUsername(@PathVariable("username") String username) {
    return userRepository.findUserByUsername(username);
  }

}
