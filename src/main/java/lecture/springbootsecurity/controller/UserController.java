package lecture.springbootsecurity.controller;


import jakarta.servlet.http.HttpSession;
import lecture.springbootsecurity.dto.UserDTO;
import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.HttpSessionRequiredException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j //로그 관련 메소드를 편리하게 사용할 수 있음.
public class UserController {
    @Autowired // service 호출
    UserService userService;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @GetMapping("") // 8080/auth로
    public String getAuth() {
        return "GET /auth";
    }

    @PostMapping("/signup")
    // ? : 와일드카드. responseEntity의 body에 어떤 값 담을 지 몰라서.
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) { // 이 함수가 받는 값은 userDTO 객체
        try {
            UserEntity user = UserEntity.builder()
                    .email(userDTO.getEmail())
                    .username(userDTO.getUsername())
                    .password(passwordEncoder.encode(userDTO.getPassword()))
                    .build(); // userDTO 값으로 엔티티를 만들어 줌..?

            UserEntity responseUser = userService.create(user);

            // 위에서 크리에이트가 잘 되면, DTO 객체를 하나 더 만들어서 받음...?
            // 응답으로 보낼 때 사용자가 입력한 비번을 보내는 게 아니라서
            // 요청의 바디와 응답의 바디는 DTO객체를 보내는 게 좋아서 하나 더 객체 만듦

            UserDTO reponseUserDTO = UserDTO.builder()
                    .email(responseUser.getEmail())
                    .username(responseUser.getUsername())
                    .id(responseUser.getId())
                    .build();


            return ResponseEntity.ok().body(reponseUserDTO);
        } catch(Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> loginUser(HttpSession session, @RequestBody UserDTO userDTO) {
        try {
            UserEntity user = userService.login(userDTO.getEmail(), userDTO.getPassword());

            if (user == null) {
                throw new RuntimeException("login failed");
            }

            UserDTO responseUserDTO = UserDTO.builder()
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .id(user.getId())
                    .build();

            // log.info()
            // log.error()
            log.warn("session id {}", session.getId());
            session.setAttribute("userId", user.getId());

            return ResponseEntity.ok().body(responseUserDTO); // body에 담아서 responseEntity로 리턴
        } catch(Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
