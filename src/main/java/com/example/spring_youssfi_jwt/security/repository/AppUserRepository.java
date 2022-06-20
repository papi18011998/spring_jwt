package com.example.spring_youssfi_jwt.security.repository;

import com.example.spring_youssfi_jwt.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
}
