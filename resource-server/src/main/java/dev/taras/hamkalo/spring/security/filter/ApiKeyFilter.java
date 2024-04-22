package dev.taras.hamkalo.spring.security.filter;

import dev.taras.hamkalo.spring.security.authentication.ApiKeyAuthentication;
import dev.taras.hamkalo.spring.security.provider.ApiKeyAuthenticationProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ApiKeyFilter extends OncePerRequestFilter {

  AuthenticationManager authenticationManager;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    try {
      var inAuth = new ApiKeyAuthentication(request.getHeader("api-key"), false);
      var outAuth = authenticationManager.authenticate(inAuth);


      SecurityContext ctx = SecurityContextHolder.createEmptyContext();
      SecurityContextHolder.setContext(ctx);
      ctx.setAuthentication(outAuth);
//      SecurityContextHolder.getContext().setAuthentication(outAuth);

    } finally {
      filterChain.doFilter(request, response);
    }
  }
}
