package com.example.spring_security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.spring_security.utils.JWTUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            if (request.getServletPath().equals("/refresh-token") || request.getServletPath().equals("/login")){
                filterChain.doFilter(request,response);
            }else{
                String authorizationToken = request.getHeader(JWTUtils.AUTHORIZATION_HEADER);
                if (authorizationToken != null && authorizationToken.startsWith(JWTUtils.AUTHORIZATION_PREFIX)){
                    try {
                        String jwt = authorizationToken.substring(JWTUtils.AUTHORIZATION_PREFIX.length());
                        Algorithm algorithm = Algorithm.HMAC256(JWTUtils.SECRET);
                        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                        //verification du token
                        DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                        String username = decodedJWT.getSubject();
                        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                        Collection<GrantedAuthority> authorities = new ArrayList<>();
                        for(String role:roles){
                            authorities.add(new SimpleGrantedAuthority(role));
                        }
                        UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username,null,authorities);
                        //Authentifcation du user
                        SecurityContextHolder.getContext().setAuthentication(user);
                        //passage au prochain filtre
                        filterChain.doFilter(request,response);
                    }catch (Exception e){
                        response.setHeader("error-message",e.getMessage());
                        response.sendError(HttpServletResponse.SC_FORBIDDEN);
                    }
                }
                else{
                    filterChain.doFilter(request,response);
                }
            }
    }
}
