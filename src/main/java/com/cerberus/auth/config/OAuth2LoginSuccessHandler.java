package com.cerberus.auth.config;

import com.cerberus.auth.dto.AuthResponse;
import com.cerberus.auth.entity.Role;
import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.RoleRepository;
import com.cerberus.auth.repository.UserRepository;
import com.cerberus.auth.security.CustomUserDetailsService;
import com.cerberus.auth.security.JwtService;
import com.cerberus.auth.security.RefreshTokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        // By the time this handler runs, Spring Security has ALREADY
        // talked to Google, exchanged the auth code, and fetched the
        // user's profile. This method starts after all of that -- we're
        // just reading what came back.
        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
        String email = oauthUser.getAttribute("email");

        // Find-or-create: first-ever Google login for this email silently
        // provisions a local account. Google has already verified this
        // email address (that's the whole point of OAuth2 as an identity
        // provider), so this user is enabled immediately -- no separate
        // verification email needed, unlike normal registration.
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new IllegalStateException("Default role not seeded"));

            User newUser = User.builder()
                    .email(email)
                    // Random, never-disclosed password. This account can
                    // ONLY authenticate via Google from now on -- nobody
                    // (including the user) knows a plaintext that hashes
                    // to this, so /api/auth/login can never succeed for it.
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .enabled(true)
                    .roles(Set.of(defaultRole))
                    .build();

            return userRepository.save(newUser);
        });

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        String accessToken = jwtService.generateAccessToken(userDetails);
        var issued = refreshTokenService.issue(userDetails.getUsername());

        AuthResponse authResponse = AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(issued.refreshToken())
                .build();

        // A real app with a frontend would redirect here instead, e.g.
        // response.sendRedirect("https://yourapp.com/oauth/callback?accessToken=...")
        // and let the frontend pick the tokens up from the URL. We return
        // JSON directly since this project has no frontend to redirect to --
        // this keeps the endpoint testable directly from a browser.
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }
}
