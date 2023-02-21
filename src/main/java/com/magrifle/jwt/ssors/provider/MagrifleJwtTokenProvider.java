package com.magrifle.jwt.ssors.provider;

import com.magrifle.jwt.ssors.autoconfigure.MagrifleResourceServerProperties;
import com.magrifle.jwt.ssors.dto.AuthenticatedUser;
import com.magrifle.jwt.ssors.exception.InvalidJwtAuthenticationException;
import com.magrifle.jwt.ssors.service.LoggedOutTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class MagrifleJwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(MagrifleJwtTokenProvider.class);

    @Value("${spring.application.name}")
    private String applicationName;

    private final MagrifleResourceServerProperties magrifleResourceServerProperties;

    private static final String SERVICE_PREFIX = "-service";

    private LoggedOutTokenService loggedOutTokenService;


    @Autowired
    public MagrifleJwtTokenProvider(@Nullable LoggedOutTokenService loggedOutTokenService, MagrifleResourceServerProperties magrifleResourceServerProperties) {
        this.magrifleResourceServerProperties = magrifleResourceServerProperties;
        if (loggedOutTokenService == null) {
            logger.warn("Skipping check for access token jti in redis because the property authentication.redis.host is not set)");
        } else {
            this.loggedOutTokenService = loggedOutTokenService;
        }
    }

    private List<GrantedAuthority> getGroupScopes(Claims claims) {
        Object scope = claims.get(magrifleResourceServerProperties.getScopeKey());
        if (scope != null) {
            Map<String, String> _scope = (HashMap) scope;
            return _scope.entrySet()
                    .stream()
                    .filter(k -> this.checkCurrentApplication(k.getKey()))
                    .map(v -> v.getValue().split(magrifleResourceServerProperties.getScopeDelimeter()))
                    .flatMap(Arrays::stream)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        return null;
    }

    private List<GrantedAuthority> getFlatScopes(Claims claims) {
        Object scope = claims.get(magrifleResourceServerProperties.getScopeKey());
        String _scope = (String) scope;
        if (scope != null) {
            return Arrays.stream(_scope.split(magrifleResourceServerProperties.getScopeDelimeter()))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        return null;
    }

    public Authentication getAuthentication(Claims claims, String accessToken) {
        String principal = String.valueOf(claims.get("id"));
        List<GrantedAuthority> authorities = magrifleResourceServerProperties.isScopesGrouped() ? getGroupScopes(claims) : getFlatScopes(claims);

        AuthenticatedUser magrifleAuthenticatedUser = new AuthenticatedUser(principal, accessToken,
                (String) claims.get("email"), (String) claims.get("phoneNumber"), authorities);

        if (claims.get("firstName") != null) {
            magrifleAuthenticatedUser.setFirstName((String) claims.get("firstName"));
        }
        if (claims.get("lastName") != null) {
            magrifleAuthenticatedUser.setLastName((String) claims.get("lastName"));
        }
        if (claims.get("countryCode") != null) {
            magrifleAuthenticatedUser.setCountryCode((String) claims.get("countryCode"));
        }
        if (claims.get("currencyCode") != null) {
            magrifleAuthenticatedUser.setCurrencyCode((String) claims.get("currencyCode"));
        }

        return magrifleAuthenticatedUser;
    }


    private boolean checkCurrentApplication(String applicationRoleKey) {
        return (!applicationRoleKey.endsWith(SERVICE_PREFIX) ? applicationRoleKey.concat(SERVICE_PREFIX) : applicationRoleKey).equalsIgnoreCase(applicationName);
    }


    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }


    public Optional<Claims> validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);
            if (loggedOutTokenService != null && loggedOutTokenService.isBlackedListedJti((String) claims.getBody().get("jti"))) {
                throw new InvalidJwtAuthenticationException("The access_token provided was already logged out");
            }
            if (claims.getBody().getExpiration().before(new Date())) {
                throw new InvalidJwtAuthenticationException("The access_token provided has expired");
            }
            return Optional.of(claims.getBody());
        } catch (ExpiredJwtException e) {
            throw new InvalidJwtAuthenticationException("The access_token provided has expired", e);
        } catch (IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("An error occurred while processing your credentials, please try again", e);
        }
    }


    private SigningKeyResolver signingKeyResolver = new SigningKeyResolverAdapter() {
        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims) {
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");

                String publicKeyContent = magrifleResourceServerProperties.getPublicKey().replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace(System.getProperty("line" +
                        ".separator"), "");

                X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));

                return kf.generatePublic(keySpecX509);

            } catch (Exception e) {
                logger.error("Could not get a signing key" + claims, e);
                throw new RuntimeException("An error occurred while verifying your identity please contact an administrator");
            }
        }
    };

    public AuthenticatedUser getTokenClaim(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(token);

            return (AuthenticatedUser) this.getAuthentication(claims.getBody(), token);
        } catch (ExpiredJwtException e) {
            return (AuthenticatedUser) this.getAuthentication(e.getClaims(), token);
        } catch (IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("An error occurred while processing your credentials, please try again", e);
        }
    }
}
