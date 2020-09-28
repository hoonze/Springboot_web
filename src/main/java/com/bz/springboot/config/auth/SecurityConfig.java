package com.bz.springboot.config.auth;

import com.bz.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 설정 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable().headers().frameOptions().disable() // h2-console 화면을 사용하기 위해 해당 옵션들을 disable한다.
                .and()
                    .authorizeRequests() //URL별 권한 관리 설정하는 옵션의 시작점, 이게 선언되어야 antMatchers를 사용할 수 있다.
                    .antMatchers("/", "/css/**", "/image/**",
                            "/js/**", "/h2-console/**").permitAll()
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                    // antMatchers : 권한관리대상을 지정하는 옵션, /등 지정된 URL들은 전체 열람, api/v1/ 주소를 가진 API는 USER권한을 가진사람만 열람 가능
                    .anyRequest().authenticated() // anyRequest: 설정된 값들 이외 나머지 URL들을 나타냄, authenticated를 추가해 나머지 URL들은 인증된 사용자들에게만 허용
                .and()
                    .logout()
                        .logoutSuccessUrl("/")
                .and()
                    .oauth2Login()
                        .userInfoEndpoint()
                            .userService(customOAuth2UserService);
    }
}
