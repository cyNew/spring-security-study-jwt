package dev.zcy.springstarter.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    public final Map<String, UserDetails> USER_MAP = new ConcurrentHashMap<>();


    public UserDetailsServiceImpl(PasswordEncoder passwordEncoder) {
        USER_MAP.put("john", User.withUsername("john")
                .password("john")
                .passwordEncoder(passwordEncoder::encode)
                .roles("ADMIN")
                .build());
        USER_MAP.put("tom", User.withUsername("tom")
                .password("tom")
                .passwordEncoder(passwordEncoder::encode)
                .roles("USER")
                .build());
        USER_MAP.put("kate", User.withUsername("kate")
                .password("kate")
                .passwordEncoder(passwordEncoder::encode)
                .roles("ADMIN", "USER")
                .build());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var user = USER_MAP.get(username);
        if (user == null) {
            throw new UsernameNotFoundException(username + " not found");
        }

        return user;
    }
}
