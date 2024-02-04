package dev.zcy.springstarter.filters;

import dev.zcy.springstarter.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_NAME = "Authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // retrieve the bear header
        var header = request.getHeader(AUTHORIZATION_NAME);

        if (header != null && header.startsWith("Bearer ")) {
            var token = header.substring(7);

            var optionalJwt = JwtUtils.parse(token);

            optionalJwt.ifPresent(userDetails -> {
                var securityContext = SecurityContextHolder.getContext();
                var authentication = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        null,
                        userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                securityContext.setAuthentication(authentication);
            });
        }

        filterChain.doFilter(request, response);
    }
}
