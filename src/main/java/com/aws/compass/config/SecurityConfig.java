package com.aws.compass.config;

import com.aws.compass.filter.JwtAuthenticationFilter;
import com.aws.compass.security.PrincipalEntryPoint;
import com.aws.compass.security.oauth2.OAuth2SuccessHandler;
import com.aws.compass.security.PrincipalUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final PrincipalEntryPoint principalEntryPoint;
    private final PrincipalUserDetailsService principalUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors();            // WebMvcConfig의 CORS 설정을 적용
        http.csrf().disable();  // CSRF 보호 비활성화
        http.authorizeRequests()
                .antMatchers("/hc", "/env")
                .permitAll()
                .antMatchers("/api/auth/**", "/api/option/**",
                        "/api/academies", "/api/academy/**",
                        "/api/review/**", "/api/purchase/**", "/api/academy/check/**",
                        "/api/ad/academies/random")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(principalEntryPoint)
                .and()
                .oauth2Login()
                .successHandler(oAuth2SuccessHandler)
                .userInfoEndpoint()
                .userService(principalUserDetailsService);
    }
}
