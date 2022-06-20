package com.example.spring_youssfi_jwt.security;

import com.example.spring_youssfi_jwt.security.entities.AppUser;
import com.example.spring_youssfi_jwt.security.services.AccountService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private AccountService accountService;

    public SecurityConfig(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = accountService.loadUserByUsername(username);
                List<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getAppRoles().forEach(appRole -> {
                    authorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
                });
                return new User(appUser.getUsername(),appUser.getPassword(),authorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.formLogin();
       http.authorizeRequests().anyRequest().authenticated();
    }
}
