package dev.taras.hamkalo.spring.security.authentication;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.With;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;


@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ApiKeyAuthentication implements Authentication {

  @Getter
  String key;

  @With
  boolean authenticated;

  @Override
  public boolean isAuthenticated() {
    return authenticated;
  }

  @Override
  public String getName() {
    return "I am NULL";
  }

  @Override
  public Object getPrincipal() {
    /*
      before passing to controller,
      SecurityParams resolver extracts principal from authentication
     */
    return this;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {}

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public boolean implies(Subject subject) {
    return Authentication.super.implies(subject);
  }
}