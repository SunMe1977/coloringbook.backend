package com.hansjoerg.coloringbook.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
public class AuthResponse {
    private String accessToken;
    private String tokenType = "Bearer";

    public AuthResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}
