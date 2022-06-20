package com.example.spring_youssfi_jwt.security.repository;

import com.example.spring_youssfi_jwt.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
