package com.vue.auth.security;

import com.vue.auth.model.User;
import com.vue.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthUserDetails implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public AuthUserDetails(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);

        if (user == null) {
            throw new UsernameNotFoundException("User details not found for the user : " + username);
        }
        return new UserDetailsSecurity(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByEmail(username);
    }
}
