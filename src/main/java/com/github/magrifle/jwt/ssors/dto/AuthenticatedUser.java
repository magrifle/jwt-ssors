package com.github.magrifle.jwt.ssors.dto;

import java.util.Collection;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@Getter
@Setter
public class AuthenticatedUser extends UsernamePasswordAuthenticationToken {

    private String id;

    private String email;

    private String phoneNumber;

    private String accessToken;

    private String firstName;

    private String lastName;
    
    private String countryCode;
    
    private String currencyCode;

    private String userType;

    public AuthenticatedUser(Object principal, String accessToken, String email, String phoneNumber,
                             Collection<? extends GrantedAuthority> authorities) {
        super(principal, "", authorities);
        this.accessToken = accessToken;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.id = principal.toString();
    }
}

