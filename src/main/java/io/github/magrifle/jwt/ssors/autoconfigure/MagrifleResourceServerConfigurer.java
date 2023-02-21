package io.github.magrifle.jwt.ssors.autoconfigure;

import io.github.magrifle.jwt.ssors.filter.MagrifleJwtTokenFilter;
import io.github.magrifle.jwt.ssors.provider.MagrifleJwtTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Component
public class MagrifleResourceServerConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>
{

    private final MagrifleJwtTokenProvider magrifleJwtTokenProvider;

    @Override
    public void configure(HttpSecurity http)
    {
        http.addFilterBefore(new MagrifleJwtTokenFilter(magrifleJwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
    }

}
