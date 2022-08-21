package com.vue.auth.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vue.auth.constants.SecurityConstants;
import com.vue.auth.model.User;
import com.vue.auth.security.AuthUserDetails;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class JWTTokenGeneratorFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final AuthUserDetails authUserDetails;

    public JWTTokenGeneratorFilter(AuthenticationManager authenticationManager, AuthUserDetails authUserDetails) {
        this.authenticationManager = authenticationManager;
        this.authUserDetails = authUserDetails;
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {

        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            User credentials = new ObjectMapper().readValue(request.getInputStream(), User.class);
            authenticationToken = new UsernamePasswordAuthenticationToken(
                    credentials.getEmail(),
                    credentials.getPassword(),
                    new ArrayList<>());
        } catch (IOException e) {
            logger.error("Error while trying to authenticate" + e);
        }
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException {

        User user = authUserDetails.findByUsername(authResult.getName());

        if (authResult.getPrincipal() != null) {
            SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
            String jwtToken = Jwts.builder().setIssuer("Pollongz").setSubject("JWT Token")
                    .claim("username", authResult.getName())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + 300000000))
                    .signWith(key).compact();
            response.setHeader(SecurityConstants.JWT_HEADER, jwtToken);

            String json = new ObjectMapper().writeValueAsString(user);
            response.getWriter().write(json);
            response.flushBuffer();
        }
    }
}
