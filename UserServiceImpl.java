package com.hcl.mi.servicesImpl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hcl.mi.entities.User;
import com.hcl.mi.exceptions.GenericAlreadyExistsException;
import com.hcl.mi.repositories.UserRepository;
import com.hcl.mi.requestdtos.NewUser;
import com.hcl.mi.services.UserService;


@Service
public class UserServiceImpl implements UserService, UserDetailsService {

//    @Autowired
//    private UserRepository userRepo;
//
//    @Autowired
//    @Lazy
//    private PasswordEncoder passwordEncoder;
	
    private final UserRepository userRepo;

    private final PasswordEncoder passwordEncoder;
    
    
    @Lazy
	public UserServiceImpl(UserRepository userRepo, PasswordEncoder passwordEncoder) {
		super();
		this.userRepo = userRepo;
		this.passwordEncoder = passwordEncoder;
	} 
    
    
    @Override
    public void saveUser(NewUser user) {
        String username = user.getUsername().toLowerCase();
        String email = user.getEmail().toLowerCase();

        Optional<User> existingUser = userRepo.findByUsernameOrEmail(username, email);
        if (existingUser.isPresent()) {
            User found = existingUser.get();
            if (found.getUsername().equalsIgnoreCase(username)) {
                throw new GenericAlreadyExistsException("Username already exists");
            } else if (found.getEmail().equalsIgnoreCase(email)) {
                throw new GenericAlreadyExistsException("Email already exists");
            }
        }

        String assignedRole = (user.getRole() != null && !user.getRole().isBlank())
                ? user.getRole().toUpperCase()
                : "USER";

        User newUser = User.builder()
                .username(username)
                .password(passwordEncoder.encode(user.getPassword()))
                .email(email)
                .mobileNum(user.getMobileNum())
                .role(assignedRole)
                .build();

        userRepo.save(newUser);
    }



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.hcl.mi.entities.User u = userRepo.findByUsername(username.toLowerCase())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(u.getUsername())
                .password(u.getPassword())
                .roles(u.getRole())
                .build();
    }

    @Override
    public boolean checkUserCredentails(String username, String password) {
        Optional<User> optionalUser = userRepo.findByUsername(username);

        if (optionalUser.isEmpty()) {
            return false;
        }

        User user = optionalUser.get();

        // assuming password is stored in encoded form (recommended)
        return passwordEncoder.matches(password, user.getPassword());
    }

}

