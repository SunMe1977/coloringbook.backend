package com.hansjoerg.coloringbook.controller;

import com.hansjoerg.coloringbook.exception.ResourceNotFoundException;
import com.hansjoerg.coloringbook.model.User;
import com.hansjoerg.coloringbook.repository.UserRepository;
import com.hansjoerg.coloringbook.security.CurrentUser;
import com.hansjoerg.coloringbook.security.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "error.resourceNotFound", // Message key
                        new Object[]{"User", "id", userPrincipal.getId()}, // Arguments for the message
                        "User", // Resource name (for backward compatibility/context)
                        "id", // Field name (for backward compatibility/context)
                        userPrincipal.getId() // Field value (for backward compatibility/context)
                ));
    }
}
