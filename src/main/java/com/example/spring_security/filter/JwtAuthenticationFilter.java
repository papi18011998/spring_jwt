package com.example.spring_security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.spring_security.utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Value("${jwt.secret}")
    private String secret;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // Si on tente de s'authentifier
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken  authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(authenticationToken);
    }

    // Si l'authentification passe avec succes
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
       // utilisateur authentifie obtenu
        User user = (User) authResult.getPrincipal();

        //Generation du token
        Algorithm algorithm =Algorithm.HMAC256(JWTUtils.SECRET);
         String jwtAccessToken = JWT.create()
                 .withSubject(user.getUsername())
                 .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRE_ACCESS_TOKEN))
                 .withIssuedAt(new Date())
                 .withIssuer(request.getRequestURL().toString())
                 .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                 .sign(algorithm);

        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRE_REFRESH_TOKEN))
                .withIssuedAt(new Date())
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        //renvoie du refresh token au niveau du corps de la reponse
        Map<String,String> idToken = new HashMap<>();
        idToken.put("access-token",jwtAccessToken);
        idToken.put("refresh-token",jwtRefreshToken);
        //renvoi du access token sur le header
        response.setHeader(JWTUtils.AUTHORIZATION_HEADER,jwtAccessToken);
        //renvoie des donnees au format json
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
        response.setContentType("application/json");
    }
}
