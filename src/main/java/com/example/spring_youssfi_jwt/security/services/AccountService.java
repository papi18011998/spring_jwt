package com.example.spring_youssfi_jwt.security.services;

import com.example.spring_youssfi_jwt.security.entities.AppRole;
import com.example.spring_youssfi_jwt.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUser();
}
