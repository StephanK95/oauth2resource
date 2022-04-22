package com.klamann.oauth2resource.security;

import com.klamann.oauth2resource.accessToken.AccessTokenEntry;
import com.klamann.oauth2resource.accessToken.AccessTokenVerifier;
import com.klamann.oauth2resource.scope.ScopeVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private AccessTokenEntry accessTokenEntry;

    @Autowired
    public ApplicationSecurityConfig(AccessTokenEntry accessTokenEntry) {
        this.accessTokenEntry = accessTokenEntry;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .addFilterAfter(new AccessTokenVerifier(accessTokenEntry), BasicAuthenticationFilter.class)
                .addFilterAfter(new ScopeVerifier(accessTokenEntry), AccessTokenVerifier.class)
                .authorizeRequests()
                .antMatchers("/api/v1/students").permitAll()
                .antMatchers("/**").denyAll()
                .anyRequest().authenticated()
                .and()
                .httpBasic().disable();
    }
}
