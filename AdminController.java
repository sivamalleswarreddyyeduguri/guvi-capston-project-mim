package com.hcl.mi.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.hcl.mi.requestdtos.NewUser;
import com.hcl.mi.responsedtos.ResponseDto;
import com.hcl.mi.services.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private static final Logger LOG = LoggerFactory.getLogger(AdminController.class);

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/create-inspector")
    public ResponseEntity<ResponseDto> createInspector(@Valid @RequestBody NewUser newUser) {
        newUser.setRole("INSPECTOR");
        userService.saveUser(newUser);
        
            LOG.info("Inspector created: {}", newUser.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED)
            		.body(new ResponseDto("201", "registration successfull"));  
        
    }

    @PostMapping("/create-user")
    public ResponseEntity<?> createUser(@Valid @RequestBody NewUser newUser) {
        newUser.setRole("USER");
       userService.saveUser(newUser);
        
            LOG.info("User created by admin: {}", newUser.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED).build();
        
    }
}
