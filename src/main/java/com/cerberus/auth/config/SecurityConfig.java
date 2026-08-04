package com.cerberus.auth.config;

import com.cerberus.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt: a deliberately slow hashing algorithm (unlike MD5/SHA which
        // are fast -- fast is bad for passwords, it's what makes brute-force
        // cracking feasible). BCrypt also auto-generates and stores a unique
        // salt per password, so two users with the same password get
        // completely different hashes in the database.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        // The AuthenticationProvider is what actually checks "does this
        // password match?" during login. We tell it which UserDetailsService
        // to fetch users from, and which encoder to verify passwords with.
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // The AuthenticationManager is what our login endpoint calls to
        // actually attempt authentication. Spring assembles it for us from
        // the AuthenticationProvider above.
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // safe here -- see explanation above;
                                                 // this is stateless, cookie-free auth
                .authorizeHttpRequests(auth -> auth
                        // Anyone can hit register/login -- that's the whole point,
                        // you're not authenticated *yet* when calling these.
                        .requestMatchers("/api/auth/**").permitAll()
                        // Swagger docs stay open too, purely for local dev convenience.
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        // Everything else requires a valid JWT.
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider())
                // Insert our filter to run BEFORE Spring's default
                // username/password filter, so JWT auth is checked first.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
