package lecture.springbootsecurity.config;

import lecture.springbootsecurity.security.CustomAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

// 3.x 버전
@Configuration // 스프링 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // Spring Security 를 사용함
public class WebSecurityConfig {

    @Autowired
    CustomAuthFilter customAuthFilter;

    // 비밀번호 암호화
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean // 스프링 컨테이너에서 관리
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // http 객체를 하나 받음
            // 스프링 시큐리티 적용하면, 기본적으로 모든 경로에 인증이 있어야 접근이 가능해짐
            // 특정 경로에서 인증 없이 접근할 수 있도록 설정.

            http
                    .cors(Customizer.withDefaults())
                    .csrf(CsrfConfigurer::disable) // post, put 요청을 허용
                    .logout(auth -> auth
                            .logoutUrl("/auth/logout")
                            .logoutSuccessHandler((request, response, authentication) -> {
                                response.setStatus(200);
                            })
                    )
                    .authorizeHttpRequests(authorize->authorize
                    .requestMatchers("/auth/**").permitAll()
//                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated() // 위의 주소 말고 나머지 모든 주소들은 로그인 되어야 접속 가능
            );
            // authorizedHttpRequests 대표적인 메소드들
            // .permitAll() : 권한 없이 접속 가능하다.
            // .authenticated() : 로그인이 필요하다.
            // .hasRole("권한? ex.ADMIN") : 특정 권한이 있어야 접속 가능
            //  ex. ADMIN 의 권한이 있다면 이런 메소드 쓸 수 있음

            // 만들어둔 custom 필터 등록
            http.addFilterAfter(customAuthFilter, UsernamePasswordAuthenticationFilter.class);

            return http.build(); // 빌드의 반환값이 SecurityFilterChain이 됨.

    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // cors 설정
        config.setAllowCredentials(true); // 실제 응답을 보낼 때, 브라우저에게 자격 증명과 함께 요청을 보낼 수 있도록 허용합니다.
        config.setAllowedOriginPatterns(Arrays.asList("*")); // 모든 원본에서의 요청을 허용합니다.
        config.setAllowedMethods(Arrays.asList("HEAD","POST","GET","DELETE","PUT", "PATCH")); // 허용할 HTTP 메서드를 설정합니다.
        config.setAllowedHeaders(Arrays.asList("*")); // 모든 헤더의 요청을 허용합니다.


        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config); // 모든 경로에 대해 위에서 설정한 CORS 설정을 적용합니다.

        return source;
    };
}
    // 2.x 버전
//    public class WebSecurityConfig extends SecurityConfigurerAdapter {
//        public configure() {}
//    }


