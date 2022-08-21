package com.vue.auth.config;

import com.vue.auth.filter.JWTTokenGeneratorFilter;
import com.vue.auth.filter.JWTTokenValidatorFilter;
import com.vue.auth.repository.UserRepository;
import com.vue.auth.security.AuthUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
public class AuthSecurityConfig {

    private final AuthUserDetails authUserDetails;
    private final UserRepository userRepository;

    @Autowired
    public AuthSecurityConfig(AuthUserDetails authUserDetails, UserRepository userRepository) {
        this.authUserDetails = authUserDetails;
        this.userRepository = userRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(this.authUserDetails);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .cors().configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setMaxAge(3600L);
                    return config;
                }).and().csrf().disable()
                .addFilter(new JWTTokenGeneratorFilter(authentication -> authentication, authUserDetails))
                .addFilter(new JWTTokenValidatorFilter(authentication -> authentication, this.userRepository))
                .authorizeHttpRequests((auth) -> auth
                        .antMatchers("/login").permitAll()
                        .antMatchers("/home").authenticated()
                        .antMatchers("/register").hasAnyRole("USER", "ADMIN")
                ).httpBasic(Customizer.withDefaults());
        return http.build();
    }
}

