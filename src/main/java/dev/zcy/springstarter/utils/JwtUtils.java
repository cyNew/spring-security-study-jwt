package dev.zcy.springstarter.utils;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;


@Slf4j
public class JwtUtils {
    private static final String key = "Spring-Security-JWT-KEY";
    private static final Algorithm algorithm = Algorithm.HMAC256(key.getBytes());
    private static final long expireTime = TimeUnit.MINUTES.toMillis(5);

    public static String generate(UserDetails userDetails) {

        Objects.requireNonNull(userDetails);

        var now = Instant.now();
        var expiredAt = now.plusMillis(expireTime);

        return JWT.create()
                .withSubject("jwt")
                .withIssuer("SpringSecurityJwt")
                .withIssuedAt(now)
                .withNotBefore(now)
                .withExpiresAt(expiredAt)
                .withClaim("username", userDetails.getUsername())
                .withClaim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .distinct()
                        .toList())
                .sign(algorithm);
    }


    public static Optional<UserDetails> parse(String token) {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("SpringSecurityJwt")
                .build();

        try {
            DecodedJWT verify = verifier.verify(token);
            if (verify.getExpiresAtAsInstant().isBefore(Instant.now())) {
                return Optional.empty();
            }

            var username = verify.getClaim("username").asString();
            var authorities = verify.getClaim("authorities").asList(String.class);

            UserDetails userDetails = User.withUsername(username)
                    .password("")
                    .authorities(authorities.toArray(String[]::new))
                    .build();

            return Optional.of(userDetails);
        } catch (JWTVerificationException e) {
            log.error("cannot verify the token: {}", token);
            return Optional.empty();
        }
    }
}
