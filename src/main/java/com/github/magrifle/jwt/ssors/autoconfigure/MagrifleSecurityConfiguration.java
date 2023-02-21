package com.github.magrifle.jwt.ssors.autoconfigure;

import com.github.magrifle.jwt.ssors.provider.MagrifleJwtTokenProvider;
import com.github.magrifle.jwt.ssors.service.LoggedOutTokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
@ComponentScan(basePackageClasses = {MagrifleJwtTokenProvider.class, MagrifleResourceServerConfigurer.class, LoggedOutTokenService.class})
public class MagrifleSecurityConfiguration {
    private final MagrifleResourceServerConfigurer magrifleResourceServerConfigurer;

    public MagrifleSecurityConfiguration(MagrifleResourceServerConfigurer magrifleResourceServerConfigurer) {
        this.magrifleResourceServerConfigurer = magrifleResourceServerConfigurer;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) ->
                        authz.requestMatchers("/actuator/**").permitAll()
                                .anyRequest().permitAll())
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .apply(magrifleResourceServerConfigurer);
        return http.build();
    }
}
