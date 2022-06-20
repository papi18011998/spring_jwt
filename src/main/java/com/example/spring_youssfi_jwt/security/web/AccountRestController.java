package com.example.spring_youssfi_jwt.security.web;

import com.example.spring_youssfi_jwt.security.entities.AppRole;
import com.example.spring_youssfi_jwt.security.entities.AppUser;
import com.example.spring_youssfi_jwt.security.services.AccountService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController

public class AccountRestController {
    private final AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    public List<AppUser> list(){
     return accountService.listUser();
    }
    @PostMapping(path = "/users")
    public AppUser addUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    public AppRole addRole (@RequestBody AppRole appRole){
        return  accountService.addNewRole(appRole);
    }
    @PostMapping(path = "addRoleToUser")
    public  void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
}
@Data
class  RoleUserForm{
    private String username;
    private  String roleName;
}
