//package com.hcl.mi.controllers;
//
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import com.hcl.mi.requestdtos.NewUser;
//import com.hcl.mi.services.UserService;
//
//import jakarta.validation.Valid;
//
//@RestController
//@RequestMapping("/user")
//
//public class UserController {
//
//	private static Logger LOGGER = LoggerFactory.getLogger(UserController.class);
//
//	@Autowired 
//	private UserService userService;
//	
//
//	    @PostMapping("/register")
//	    public ResponseEntity<String> registerUser(@RequestBody @Valid NewUser newUser) {
//	        boolean saved = userService.saveUser(newUser);
//	        if (!saved) {
//	            return ResponseEntity.badRequest().body("Username already exists");
//	        }
//	        return ResponseEntity.ok("User registered successfully");
//	    }
//
//
//	@PostMapping("/login/{username}/{password}")
//	public ResponseEntity<?> login(@PathVariable String username, @PathVariable String password) {
//		boolean isValidUser = userService.checkUserCredentails(username, password);
//
//		if (isValidUser) {
//			LOGGER.info("successfull login from user : {}", username);
//			return new ResponseEntity<>(HttpStatus.OK);
//		} else {
//			LOGGER.warn("Unauthorized accessing to account : {}", username);
//			return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
//		}
//	}
//
//}

package com.hcl.mi.controllers;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hcl.mi.requestdtos.LoginRequestDto;
import com.hcl.mi.requestdtos.NewUser;
import com.hcl.mi.responsedtos.ResponseDto;
import com.hcl.mi.security.JwtUtil;
import com.hcl.mi.services.UserService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/user")
public class UserController {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final org.springframework.security.core.userdetails.UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    public UserController(UserService userService,
                          org.springframework.security.core.userdetails.UserDetailsService userDetailsService,
                          JwtUtil jwtUtil) {
        this.userService = userService;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    // public registration - always default role USER
	@PostMapping("/register")
	public ResponseEntity<ResponseDto> register(@Valid @RequestBody NewUser newUser) {
		userService.saveUser(newUser);

		LOGGER.info("New user registered: {}", newUser.getUsername());
		return ResponseEntity.status(HttpStatus.CREATED).body(new ResponseDto("201", "user registered successfully"));

	}

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        boolean ok = userService.checkUserCredentails(username, password);
        if (!ok) {
            LOGGER.warn("Unauthorized login attempt: {}", username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials"));
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        String token = jwtUtil.generateToken(userDetails);

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("username", username);
        response.put("roles", userDetails.getAuthorities()
                .stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.toList()));

        LOGGER.info("User logged in: {}", username);
        return ResponseEntity.ok(response);
    }


}

