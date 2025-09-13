package com.hansjoerg.coloringbook.security;


import com.hansjoerg.coloringbook.exception.ResourceNotFoundException;
import com.hansjoerg.coloringbook.model.User;
import com.hansjoerg.coloringbook.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private MessageSource messageSource;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    String errorMessage = messageSource.getMessage("error.userNotFound", new Object[]{email}, LocaleContextHolder.getLocale());
                    return new UsernameNotFoundException(errorMessage);
                });

        return UserPrincipal.create(user);
    }

    @Transactional
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException("error.resourceNotFound", new Object[]{"User", "id", id}, "User", "id", id)
        );

        return UserPrincipal.create(user);
    }
}
