package com.example.spring_security.service;

import com.example.spring_security.model.AppRole;
import com.example.spring_security.model.AppUser;

import java.util.List;

public interface AccountService {
    public AppUser addNewUser(AppUser appUser);
    public AppRole addNewRole(AppRole appRole);
    public void addRoleToUser(String username,String roleName);
    public AppUser loadUserByUsername(String username);
    public List<AppUser> listUsers();
}
