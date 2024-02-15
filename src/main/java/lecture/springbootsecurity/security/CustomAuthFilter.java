package lecture.springbootsecurity.security;
// 1.  세션 기반 인증 방식
// -- 로그인에 성공 > session에 userID저장
// -- 로그인 여부를 판단하고 싶을 때 > session에 userId가 있는지 없는지에 따라
// -- 존재하면, 로그인을 한사람. 존재하지 않으면 로그인을 하지 않은 사람
// -- 로그아웃 시에 세션에서 로그인 정보 삭제 > 즉 서버에서 처리

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
          HttpSession session = request.getSession(); // session 가져오기
            log.warn("session id {}", session.getId()); // session 로그 찍어보기
            Object userId = session.getAttribute("userId");

            // session에 userId가 있는지 없는지 확인
            if(userId != null) {
                // 1.  사용자 정보를 담는 공간? 토큰 생성
                Authentication authentication = new UsernamePasswordAuthenticationToken(String.valueOf(userId), null, AuthorityUtils.NO_AUTHORITIES);

                // 2. SecurityContextHolder 에 authentication 정보를 넣음. set
                // SecurityContextHolder :  클라이언트의 요청 ->  응답 사이에 일시적으로 auth 정보를 저장할 수 있는 공간으로 생각하면 됨.
                SecurityContextHolder.getContext().setAuthentication(authentication);
//                SecurityContextHolder.getContext().getAuthenciation().getPrincipal();

            }

        } catch (Exception e) {
            log.error("filter error {}", e.getMessage());
        }

        filterChain.doFilter(request, response);

    }
}
