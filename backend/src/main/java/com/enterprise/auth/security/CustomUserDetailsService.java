package com.enterprise.auth.security;

import com.enterprise.auth.entity.User;
import com.enterprise.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(identifier.trim())
                .or(() -> userRepository.findByEmail(identifier.trim().toLowerCase()))
                .orElseThrow(() -> new UsernameNotFoundException("No user found with identifier: " + identifier));

        return new CustomUserDetails(user);
    }
}
