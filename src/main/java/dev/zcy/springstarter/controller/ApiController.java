package dev.zcy.springstarter.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/hello")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
    }
}
