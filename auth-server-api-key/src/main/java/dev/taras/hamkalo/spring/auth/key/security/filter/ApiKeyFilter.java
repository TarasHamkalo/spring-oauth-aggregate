package dev.taras.hamkalo.spring.auth.key.security.filter;

import dev.taras.hamkalo.spring.auth.key.security.authentication.ApiKeyAuthentication;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//@Component
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ApiKeyFilter extends OncePerRequestFilter {

  AuthenticationManager authenticationManager;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    var requestKey = request.getHeader("api-key");
    if (requestKey == null || "null".equals(requestKey)) {
      filterChain.doFilter(request, response);
      return;
    }

    var inAuth = new ApiKeyAuthentication(null, requestKey);

    var outAuth = authenticationManager.authenticate(inAuth);

    SecurityContextHolder.getContext().setAuthentication(outAuth);
    filterChain.doFilter(request, response);
  }
}
