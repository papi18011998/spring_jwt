package com.example.spring_security;

import com.example.spring_security.model.AppRole;
import com.example.spring_security.model.AppUser;
import com.example.spring_security.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
    @Bean
    CommandLineRunner start(AccountService accountService){
        return args -> {
             final String ROLE_USER ="USER";
             final String ROLE_ADMIN ="ADMIN";
             final String ROLE_CUSTOMER_MANAGER ="CUSTOMER_MANAGER";
             final String ROLE_PRODUCT_MANAGER ="PRODUCT_MANAGER";
             final String ROLE_BILLS_MANAGER ="BILLS_MANAGER";

             accountService.addNewRole(new AppRole(null,ROLE_USER));
             accountService.addNewRole(new AppRole(null,ROLE_ADMIN));
             accountService.addNewRole(new AppRole(null,ROLE_CUSTOMER_MANAGER));
             accountService.addNewRole(new AppRole(null,ROLE_PRODUCT_MANAGER));
             accountService.addNewRole(new AppRole(null,ROLE_BILLS_MANAGER));

            accountService.addNewUser(new AppUser(null,"admin","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user2","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user3","1234",new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user4","1234",new ArrayList<>()));

            accountService.addRoleToUser("admin",ROLE_USER);
            accountService.addRoleToUser("admin",ROLE_ADMIN);
            accountService.addRoleToUser("user1",ROLE_USER);
            accountService.addRoleToUser("user2",ROLE_USER);
            accountService.addRoleToUser("user2",ROLE_CUSTOMER_MANAGER);
            accountService.addRoleToUser("user3",ROLE_USER);
            accountService.addRoleToUser("user3",ROLE_PRODUCT_MANAGER);
            accountService.addRoleToUser("user4",ROLE_USER);
            accountService.addRoleToUser("user4",ROLE_BILLS_MANAGER);
        };
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
