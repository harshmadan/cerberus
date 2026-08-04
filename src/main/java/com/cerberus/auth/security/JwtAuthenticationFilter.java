package com.cerberus.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// OncePerRequestFilter guarantees this filter runs exactly one time per
// request, even in environments that might otherwise dispatch a request
// through the filter chain more than once (e.g. internal forwards).
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // No "Bearer <token>" header at all -- not our concern, let the
        // request continue down the chain. It'll simply be treated as
        // unauthenticated, and whatever endpoint it hits decides if that's
        // allowed (this is where SecurityConfig's rules take over).
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7); // strip "Bearer " prefix
        final String userEmail = jwtService.extractUsername(jwt);

        // Only authenticate if there's a token AND nothing has already
        // authenticated this request in the SecurityContext yet. Prevents
        // redundant work if something upstream already set it.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,                          // credentials -- null because we're not
                                                         // re-checking a password, the JWT itself
                                                         // IS the proof of identity here
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // THIS is the line that actually matters most in this whole
                // file. Setting this tells the rest of Spring Security:
                // "trust this request, it's been authenticated." Every
                // @PreAuthorize check and .authenticated() rule downstream
                // reads from this context.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
