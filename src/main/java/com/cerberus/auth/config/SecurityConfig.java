package com.cerberus.auth.config;

import com.cerberus.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
// This is the switch that makes @PreAuthorize/@PostAuthorize annotations
// on controller/service methods actually get enforced. Without it, they'd
// silently do nothing -- Spring wouldn't even error, it just wouldn't check.
@EnableMethodSecurity
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
                .exceptionHandling(ex -> ex
                        // Fires when there's no valid authentication at all --
                        // e.g. no token, or an expired/malformed one.
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setContentType("application/json");
                            response.setStatus(401);
                            response.getWriter().write("{\"error\":\"Authentication required\"}");
                        })
                        // Fires when the request IS authenticated, but failed
                        // a @PreAuthorize check -- this is the one RBAC
                        // actually introduces today. Distinct from 401:
                        // the server knows exactly who you are, you're just
                        // not allowed to do this specific thing.
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setContentType("application/json");
                            response.setStatus(403);
                            response.getWriter().write("{\"error\":\"You do not have permission to perform this action\"}");
                        })
                )
                .authenticationProvider(authenticationProvider())
                // Insert our filter to run BEFORE Spring's default
                // username/password filter, so JWT auth is checked first.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
