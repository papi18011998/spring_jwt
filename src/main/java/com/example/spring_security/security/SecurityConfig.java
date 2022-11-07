package com.example.spring_security.security;

import com.example.spring_security.filter.JwtAuthenticationFilter;
import com.example.spring_security.filter.JwtAuthorizationFilter;
import com.example.spring_security.service.AccountService;
import com.example.spring_security.service.impl.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
   private final UserDetailsServiceImpl userDetailsServiceImpl;

    public SecurityConfig(UserDetailsServiceImpl userDetailsServiceImpl) {
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Permet de connaitre les utilisateurs qui ont le droit d'acceder
        auth.userDetailsService(userDetailsServiceImpl);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // configuraton des droits d'acces
        http.csrf().disable();
        //Activation de l'authentification stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // Si on a un systeme base sur les frames
        http.headers().frameOptions().disable();
        //verification des autorisations
        http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAnyAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/refresh-token");
        http.authorizeRequests().antMatchers("/login").permitAll()
                .anyRequest().authenticated();
        // Ajout du filtre ou middleware(laravel) pour l'authentification
        http.addFilter( new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
