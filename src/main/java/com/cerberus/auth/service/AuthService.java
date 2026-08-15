package com.cerberus.auth.service;

import com.cerberus.auth.audit.Audited;
import com.cerberus.auth.dto.AuthResponse;
import com.cerberus.auth.dto.LoginRequest;
import com.cerberus.auth.dto.RegisterRequest;
import com.cerberus.auth.entity.Role;
import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.RoleRepository;
import com.cerberus.auth.repository.UserRepository;
import com.cerberus.auth.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
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
    private final com.cerberus.auth.security.CustomUserDetailsService userDetailsService;
    private final com.cerberus.auth.security.RefreshTokenService refreshTokenService;
    private final com.cerberus.auth.security.EmailVerificationService emailVerificationService;
    private final com.cerberus.auth.security.PasswordResetService passwordResetService;
    private final MailService mailService;
    private final com.cerberus.auth.security.LoginAttemptService loginAttemptService;

    @Audited("REGISTER")
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
                // Real gate now. Registration succeeds, but login stays
                // blocked (see login() below and CustomUserDetailsService's
                // .disabled() mapping) until the emailed link is clicked.
                .enabled(false)
                .roles(Set.of(defaultRole))
                .build();

        userRepository.save(user);

        String token = emailVerificationService.issueToken(user.getEmail());
        mailService.sendVerificationEmail(user.getEmail(), token);
    }

    @Audited("EMAIL_VERIFICATION")
    public void verifyEmail(String token) {
        String email = emailVerificationService.consumeToken(token);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("User not found"));
        user.setEnabled(true);
        userRepository.save(user);
    }

    @Audited("FORGOT_PASSWORD")
    public void forgotPassword(String email) {
        // Deliberately succeeds (from the caller's point of view) whether
        // or not this email actually has an account. Responding
        // differently for "email not found" vs "email sent" would let an
        // attacker enumerate which addresses are registered users --
        // a real information leak, even though it feels harmless.
        userRepository.findByEmail(email).ifPresent(user -> {
            String token = passwordResetService.issueToken(email);
            mailService.sendPasswordResetEmail(email, token);
        });
    }

    @Audited("PASSWORD_RESET")
    public void resetPassword(String token, String newPassword) {
        String email = passwordResetService.consumeToken(token);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("User not found"));
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        // Known limitation, worth naming rather than hiding: this does NOT
        // revoke the user's existing refresh token sessions. Our Redis
        // schema keys sessions by familyId, not by user, so there's no
        // efficient way yet to find "every active session for this user."
        // A more complete system would track sessions per-user so a
        // password reset (a strong signal of compromise) could kill every
        // active session, not just require a new password going forward.
    }

    @Audited("LOGIN")
    public AuthResponse login(LoginRequest request) {
        if (loginAttemptService.isLocked(request.getEmail())) {
            throw new LockedException("Too many failed attempts -- account temporarily locked. Try again in 15 minutes.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (BadCredentialsException ex) {
            // Only WRONG PASSWORD counts toward lockout -- not every login
            // failure. A DisabledException (unverified email), for example,
            // shouldn't count against someone who simply hasn't checked
            // their inbox yet.
            loginAttemptService.recordFailure(request.getEmail());
            throw ex;
        }

        // Successful login clears the counter -- lockout is about a BURST
        // of recent failures, not a lifetime tally.
        loginAttemptService.resetAttempts(request.getEmail());

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String accessToken = jwtService.generateAccessToken(userDetails);

        var issued = refreshTokenService.issue(userDetails.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(issued.refreshToken())
                .build();
    }

    @Audited("REFRESH_TOKEN")
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

    @Audited("LOGOUT")
    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }
}
