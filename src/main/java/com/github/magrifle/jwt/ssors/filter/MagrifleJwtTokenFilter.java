package com.github.magrifle.jwt.ssors.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.magrifle.jwt.ssors.dto.ErrorResponse;
import com.github.magrifle.jwt.ssors.exception.InvalidJwtAuthenticationException;
import com.github.magrifle.jwt.ssors.provider.MagrifleJwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;


import java.io.IOException;

public class MagrifleJwtTokenFilter extends GenericFilterBean {
    private final MagrifleJwtTokenProvider magrifleJwtTokenProvider;

    private static final Logger logger = LoggerFactory.getLogger(MagrifleJwtTokenFilter.class);

    public MagrifleJwtTokenFilter(MagrifleJwtTokenProvider magrifleJwtTokenProvider) {
        this.magrifleJwtTokenProvider = magrifleJwtTokenProvider;
    }


    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
            throws IOException {
        try {
            String token = magrifleJwtTokenProvider.resolveToken((HttpServletRequest) req);
            if (token != null) {
                magrifleJwtTokenProvider.validateToken(token).ifPresent(claimsJws -> {
                    Authentication auth = magrifleJwtTokenProvider.getAuthentication(claimsJws, token);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                });
            }

            filterChain.doFilter(req, res);
        } catch (Throwable e) {
            ErrorResponse errorResponse = new ErrorResponse(e.getMessage());
            if (e instanceof InvalidJwtAuthenticationException) {
                logger.warn("Could not authorize the access_token", e);
                ((HttpServletResponse) res).setStatus(HttpStatus.UNAUTHORIZED.value());
            } else {
                logger.error("Could not authorize the access_token", e);
                ((HttpServletResponse) res).setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
            res.setContentType(MediaType.APPLICATION_JSON_VALUE);
            res.getWriter().write(convertObjectToJson(errorResponse));
        }
    }


    private String convertObjectToJson(Object object) throws JsonProcessingException {
        if (object == null) {
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(object);
    }
}
