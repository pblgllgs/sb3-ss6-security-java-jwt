package com.app.dto;

import jakarta.validation.constraints.NotBlank;
import org.springframework.validation.annotation.Validated;

@Validated
public record AuthLoginRequest(
        @NotBlank String username,@NotBlank String password
) {
}
