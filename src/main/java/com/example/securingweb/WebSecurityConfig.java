package com.example.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    // Configures the security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((requests) -> requests
                        // Permits all users to access the home and root pages
                        .requestMatchers("/", "/home").permitAll()
                        // Requires authentication for any other request
                        .anyRequest().authenticated()
                )
                .formLogin((form) -> form
                        // Specifies the custom login page
                        .loginPage("/login")
                        // Allows all users to access the login page
                        .permitAll()
                )
                .logout((logout) -> logout.permitAll()); // Allows all users to log out

        return http.build();
    }

    // Defines an in-memory user store
    @Bean
    public UserDetailsService userDetailsService() {
        // Creates a default user with username 'user' and password 'password'
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(user);
    }
}
