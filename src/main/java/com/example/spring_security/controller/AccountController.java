package com.example.spring_security.controller;

import com.example.spring_security.model.AppRole;
import com.example.spring_security.model.AppUser;
import com.example.spring_security.service.AccountService;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountController {
    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("users")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping("/users")
    public AppUser saveUser(@RequestBody AppUser appUser){
      return  accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return  accountService.addNewRole(appRole);
    }

    @PostMapping("addRoleToUser")
    public void addRoleToUser(RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }
}
@Data
@NoArgsConstructor
@AllArgsConstructor
class RoleUserForm{
    private String username;
    private String roleName;

}
