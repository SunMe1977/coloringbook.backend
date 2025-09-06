package com.hansjoerg.coloringbook.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

}
