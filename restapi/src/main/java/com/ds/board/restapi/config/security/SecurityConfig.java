package com.ds.board.restapi.config.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider  jwtTokenProvider;

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable()  //rest api 기본설정을 사용하지 않음. 기본설정은 비인증시 로그인 화면으로 리다이렉트
                .csrf().disable()   //rest api csrf 보안이 필요없어서 disable
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //jwt token으로 인증하기 때문에 세션은 따로 생상하지않음
                .and()
                    .authorizeRequests()    //다음 리퀘스트에 대한 사용권한 체크
                        .antMatchers("/*/signin", "/*/signup").permitAll()  //가입 및 로그인은 누구나 접근 가능
                        .antMatchers(HttpMethod.GET, "/test/**").permitAll()    // /test/**은 GET요청은 누구나 가능
                        .anyRequest().hasRole("USER")   // 그외 나머지 요청은 모두 인증된 회원만 접근이 가능
                .and()
                    .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);    // jwt token 필터를 id/password 인증 필터 전에 넣는다?
//        super.configure(http);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/swagger-ui.html", "/v2/api-docs", "/swagger-resources/**", "/webjars/**", "/swagger/**", "/db/**");
    }
}
