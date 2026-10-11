package com.ids.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF to allow JSON POST requests
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll() // Bypass default Spring Security for now
            )
            .formLogin(form -> form.disable()) // Disable the default white login page
            .httpBasic(basic -> basic.disable());
            
        return http.build();
    }
}
