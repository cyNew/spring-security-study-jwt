package dev.zcy.springstarter.controller;

import dev.zcy.springstarter.entity.UserDto;
import dev.zcy.springstarter.utils.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(value = "/signin", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<String> signIn(UserDto userDto, HttpServletRequest request) {
        var username = userDto.getUsername();
        var password = userDto.getPassword();

        if (username.isEmpty() || password.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Your username or password was wrong!");
        }

        var unauthenticatedToken =
                UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(unauthenticatedToken);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Your username or password was wrong!");
        }

        var userDetails = User.withUsername(username)
                .password(password)
                .authorities(authentication.getAuthorities())
                .build();

        String jwt = JwtUtils.generate(userDetails);

        return ResponseEntity.ok(jwt);
    }
}
