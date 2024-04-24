package dev.taras.hamkalo.spring.auth.oauth.security.service;

import dev.taras.hamkalo.spring.auth.oauth.security.user.UserDetailsImpl;

import dev.taras.hamkalo.spring.auth.oauth.repository.UserRepository;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JpaUserDetailsService implements UserDetailsService {

  UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return userRepository.findUserByUsername(username)
      .map(UserDetailsImpl::new)
      .orElseThrow(() -> new UsernameNotFoundException(
        String.format("User with username [%s] not found", username)
      ));
  }

}
