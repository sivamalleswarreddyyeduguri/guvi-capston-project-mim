package com.hcl.mi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.hcl.mi.security.JwtAccessDeniedHandler;
import com.hcl.mi.security.JwtAuthenticationEntryPoint;
import com.hcl.mi.security.JwtAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final JwtAuthenticationEntryPoint entryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            JwtAuthenticationFilter jwtFilter,
            JwtAuthenticationEntryPoint entryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.jwtFilter = jwtFilter;
        this.entryPoint = entryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint)
            		.accessDeniedHandler(jwtAccessDeniedHandler))
            .authorizeHttpRequests(auth -> auth
                // public endpoints
                .requestMatchers(HttpMethod.POST, "/user/register", "/user/login/**").permitAll()
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                // vendor
                .requestMatchers(HttpMethod.POST, "/api/v1/vendor/save").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/v1/vendor/edit").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/v1/vendor/delete/**").hasRole("ADMIN")
                .requestMatchers("/api/v1/vendor/**").hasAnyRole("ADMIN","INSPECTOR","USER")

                // plant
                .requestMatchers(HttpMethod.POST, "/plant/save").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/plant/edit").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/plant/delete/**").hasRole("ADMIN")
                .requestMatchers("/plant/**").hasAnyRole("ADMIN","INSPECTOR","USER")

                // material
                .requestMatchers(HttpMethod.POST, "/material/save").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/material/edit").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/material/delete/**").hasRole("ADMIN")
                .requestMatchers("/material/**").hasAnyRole("ADMIN","INSPECTOR","USER")

                // inspection
                .requestMatchers(HttpMethod.POST, "/insp/create/lot").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/insp/lot/edit").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/insp/save/lot/actu").hasRole("INSPECTOR")
                .requestMatchers(HttpMethod.PUT, "/insp/actu/edit").hasRole("INSPECTOR")
                .requestMatchers("/insp/**").hasAnyRole("ADMIN","INSPECTOR","USER")

                // admin endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN")

                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}