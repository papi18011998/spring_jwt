package com.example.spring_security.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.spring_security.model.AppRole;
import com.example.spring_security.model.AppUser;
import com.example.spring_security.service.AccountService;
import com.example.spring_security.utils.JWTUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountController {
    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
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
    @GetMapping(path = "refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken = request.getHeader(JWTUtils.AUTHORIZATION_HEADER);
        if(authToken!= null && authToken.startsWith(JWTUtils.AUTHORIZATION_PREFIX)){
            try {
                String refreshToken = authToken.substring(JWTUtils.AUTHORIZATION_PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JWTUtils.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                //verification du token
                DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken);
                String username = decodedJWT.getSubject();
                AppUser appUser = accountService.loadUserByUsername(username);

                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtils.EXPIRE_ACCESS_TOKEN))
                        .withIssuedAt(new Date())
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(role->role.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-token",jwtAccessToken);
                idToken.put("refresh-token",refreshToken);
                //renvoie des donnees au format json
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                response.setContentType("application/json");
                //renvoi du access token sur le header
                response.setHeader("Authorization",jwtAccessToken);
            }catch (Exception e){
                response.setHeader("error-message",e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        }else{
            throw new RuntimeException("Refresh token is required !!!");
        }
    }
    @GetMapping(path = "/profile")
    public AppUser getProfile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }
}
@Data
@NoArgsConstructor
@AllArgsConstructor
class RoleUserForm{
    private String username;
    private String roleName;

}
