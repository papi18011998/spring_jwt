package com.example.spring_security.security;

import com.example.spring_security.filter.JwtAuthenticationFilter;
import com.example.spring_security.model.AppUser;
import com.example.spring_security.service.AccountService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
   private final AccountService accountService;

    public SecurityConfig(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Permet de connaitre les utilisateurs qui ont le droit d'acceder
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
              // Recherche du login de l'utilisateur
                AppUser appUser = accountService.loadUserByUsername(username);
                //Conversion des roles en simple granted authority
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getAppRoles().forEach(appRole -> {
                    authorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
                });
                 // retour de User de spring
                return new User(appUser.getUsername(), appUser.getPassword(),authorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // configuraton des droits d'acces
        http.csrf().disable();
        //Activation de l'authentification stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // Si on a un systeme base sur les frames
        http.headers().frameOptions().disable();
        http.authorizeRequests().antMatchers("/login").permitAll()
                .anyRequest().authenticated();
        // Ajout du filtre ou middleware(laravel) pour l'authentification
        http.addFilter( new JwtAuthenticationFilter(authenticationManagerBean()));

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
