package com.cerberus.auth.security;

import com.cerberus.auth.entity.User;
import com.cerberus.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No user found with email: " + email));

        // Two kinds of authorities get flattened into one list here:
        // 1. The role itself, e.g. "ROLE_ADMIN" -- what hasRole() checks
        // 2. Every permission attached to that role, e.g. "user:delete" --
        //    what hasAuthority() checks
        // Mixing both in one list is intentional: Spring Security doesn't
        // care about the distinction internally, hasRole() just adds a
        // "ROLE_" prefix before comparing. This is what lets @PreAuthorize
        // use either style depending on how fine-grained the check needs
        // to be (Day 4 uses both, on purpose, to show the contrast).
        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .flatMap(role -> Stream.concat(
                        Stream.of(new SimpleGrantedAuthority(role.getName())),
                        role.getPermissions().stream()
                                .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                ))
                .distinct()
                .toList();

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities(authorities)
                .disabled(!user.isEnabled())          // ties into email verification, Day 5
                .accountLocked(!user.isAccountNonLocked())  // ties into rate limiting, Day 6
                .build();
    }
}
