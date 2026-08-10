package com.cerberus.auth.service;

import com.cerberus.auth.dto.AuthResponse;
import com.cerberus.auth.dto.LoginRequest;
import com.cerberus.auth.dto.RegisterRequest;
import com.cerberus.auth.entity.Role;
import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.RoleRepository;
import com.cerberus.auth.repository.UserRepository;
import com.cerberus.auth.security.CustomUserDetailsService;
import com.cerberus.auth.security.JwtService;
import com.cerberus.auth.security.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;

    public void register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            // 409 Conflict semantics -- handled by a global exception
            // handler we'll add shortly. For now this just throws.
            throw new IllegalStateException("An account with this email already exists");
        }

        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("Default role not seeded -- check DataSeeder"));

        User user = User.builder()
                .email(request.getEmail())
                // Never store the raw password -- encode() runs BCrypt here,
                // this is the ONE place in the whole app a plaintext
                // password should ever be touched.
                .password(passwordEncoder.encode(request.getPassword()))
                // TEMPORARY: true for now so you can test login today.
                // On Day 5 this flips to false-by-default, and login gets
                // blocked until the user clicks a verification link --
                // that's the actual point of building email verification.
                .enabled(true)
                .roles(Set.of(defaultRole))
                .build();

        userRepository.save(user);
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String accessToken = jwtService.generateAccessToken(userDetails);

        var issued = refreshTokenService.issue(userDetails.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(issued.refreshToken())
                .build();
    }

    public AuthResponse refresh(String refreshToken) {
        // rotate() does all the real work: validates, detects reuse, and
        // issues the new token. If it throws, our GlobalExceptionHandler
        // turns that into a 401 -- we don't need to handle it here.
        var result = refreshTokenService.rotate(refreshToken);

        UserDetails userDetails = userDetailsService.loadUserByUsername(result.subjectEmail());
        String newAccessToken = jwtService.generateAccessToken(userDetails);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(result.refreshToken())
                .build();
    }

    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }
}
