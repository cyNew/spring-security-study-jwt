package dev.zcy.springstarter;

import dev.zcy.springstarter.utils.JwtUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;

@SpringBootTest
public class JwtUtilsTests {

    @Test
    public void testEncode() {
        var userDetails = User.withUsername("rainman")
                .password("rainman")
                .authorities("ADMIN")
                .build();

        String token = JwtUtils.generate(userDetails);

        System.out.println(token);
    }
}
