//package com.hcl.mi;
//
//
//
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.transaction.annotation.EnableTransactionManagement;
//
//import io.swagger.v3.oas.annotations.OpenAPIDefinition;
//import io.swagger.v3.oas.annotations.info.Contact;
//import io.swagger.v3.oas.annotations.info.Info;

jwt:
  secret: ${JWT_SECRET:YXBs1WfPnt3hPEirCjnq6zGXBhp5naYUH/aVV9si5y4=}
  validity-ms: ${JWT_VALIDITY_MS:3600000}
            password-validation: "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!*()]).{8,}$"


//public class MaterialInspectionRestApplication {
//
//	public static void main(String[] args) {
//		SpringApplication.run(MaterialInspectionRestApplication.class, args);
//		
//	}
//
//}

package com.hcl.mi;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.hcl.mi.entities.User;
import com.hcl.mi.repositories.UserRepository;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;

@SpringBootApplication
@EnableTransactionManagement
@OpenAPIDefinition(info = @Info(title = "Material Inspection Service", 
                                description = "Capturing Inspection Actuals details.",
                                contact = @Contact(name = "Siva", 
                                email = "siva@hcltech.com")))
public class MaterialInspectionRestApplication {

    public static void main(String[] args) {
        SpringApplication.run(MaterialInspectionRestApplication.class, args);
    }

    @Bean
    CommandLineRunner initDefaultAdmin(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            String adminUsername = "admin";
            if (userRepository.findByUsername(adminUsername).isEmpty()) {
                User admin = User.builder()
                        .username(adminUsername)
                        .password(passwordEncoder.encode("Admin@123"))
                        .email("admin@hcltech.com")
                        .mobileNum("")
                        .role("ADMIN")
                        .build();
                userRepository.save(admin);
                System.out.println("Default admin created -> username: admin / password: Admin@123");
            }
        };
    }
}

