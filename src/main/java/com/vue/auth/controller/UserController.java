package com.vue.auth.controller;

import com.vue.auth.model.User;
import com.vue.auth.security.AuthUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/user")
public class UserController {

    private final AuthUserDetails authUserDetails;

    @Autowired
    public UserController(AuthUserDetails authUserDetails) {
        this.authUserDetails = authUserDetails;
    }

    @GetMapping
    public User getUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        return authUserDetails.findByUsername(email);
    }
}
