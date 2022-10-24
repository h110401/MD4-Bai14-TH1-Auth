package rikkei.academy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.request.SignInForm;
import rikkei.academy.dto.request.SignUpForm;
import rikkei.academy.dto.response.JwtResponse;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.model.User;
import rikkei.academy.security.jwt.JwtProvider;
import rikkei.academy.security.userprincipal.UserPrincipal;
import rikkei.academy.service.role.IRoleService;
import rikkei.academy.service.user.IUserService;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping(value = "/api/auth")
public class AuthController {
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    IUserService userService;
    @Autowired
    IRoleService roleService;
    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(
            @Valid
            @RequestBody
            SignUpForm signUpRequest
    ) {
        if (userService.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity<>(new ResponseMessage("Username already exists!"), HttpStatus.OK);
        }
        if (userService.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("Email already in use!"), HttpStatus.OK);
        }
        User user = new User();
        user.setName(signUpRequest.getName());
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

//        Set<String> strRoles = signUpRequest.getRoles();
//        Set<Role> roles = new HashSet<>();
//
//        strRoles.forEach(role -> {
//            switch (role) {
//                case "admin":
//                    Role adminRole = roleService.findByName(RoleName.ADMIN)
//                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//                    roles.add(adminRole);
//
//                    break;
//                case "pm":
//                    Role pmRole = roleService.findByName(RoleName.PM)
//                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//                    roles.add(pmRole);
//
//                    break;
//                default:
//                    Role userRole = roleService.findByName(RoleName.USER)
//                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//                    roles.add(userRole);
//            }
//        });

        Set<Role> roles = new HashSet<>();
        Optional<Role> role = roleService.findByName(RoleName.USER);
        if (!role.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("Role not exists!"), HttpStatus.OK);
        } else {
            roles.add(role.get());
        }
        user.setRoles(roles);
        userService.save(user);
        return new ResponseEntity<>(new ResponseMessage("User registered successfully!"), HttpStatus.CREATED);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(
            @Valid
            @RequestBody
            SignInForm loginRequest
    ) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateJwtToken(authentication);
        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();
//        Long id, String token, String type, String name, String email, Collection<? extends GrantedAuthority > roles
        return ResponseEntity.ok(new JwtResponse(userDetails.getId(), jwt, userDetails.getName(), userDetails.getEmail(), userDetails.getAuthorities()));

    }
}
