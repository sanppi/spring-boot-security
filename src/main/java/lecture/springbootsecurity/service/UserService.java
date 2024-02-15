package lecture.springbootsecurity.service;

import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

// 1. 유저 생성 2. 로그인 -> 이 두 로직
@Service // 스프링컨테이너가 얘를 서비스로서 활용할 수 있게 됨.
public class UserService {
    @Autowired
    private UserRepository userRepository; // repository 있어야. 레포지터리 객체 하나 생성.

    // 암호화를 위해 PasswordEncoder 객체 하나 만들어놔야 함.
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public UserEntity create(UserEntity userEntity){ // 회원가입할 때 사용될 메소드
        // 이메일이 중복되지 않도록 처리, 이메일 중복되면 가입 안되게
        if(userEntity == null) {
            throw new RuntimeException("entity null");
        }
        // if 문에 안 들어올 경우 이 코드 읽게 됨
        // 중복 이메일 불가
        String email = userEntity.getEmail(); // email 조회해봄

        if(userRepository.existsByEmail(email)) {
            throw new RuntimeException("이미 존재하는 이메일");
        }

        return userRepository.save(userEntity);
    }

    // [before] 암호화를 적용하기 전
    // 그냥 비밀번호를 넘기지 말고 사용자가 넘긴 비밀번호를 암호화해서 넘겨줘야 함.
//    public UserEntity login(String email, String password) {
//        return userRepository.findByEmailAndPassword(email, password);
//    } // email 이랑 password 를 return

    // [after] 암호화를 적용한 후
    public UserEntity login(String email, String password) {
        UserEntity searchUser = userRepository.findByEmail(email);

        // 암호화된 password 가 db에 있다고 가정. 여기서 password 는 암호화 안된 password. 이걸 뒤의 암호화된 거랑 비교
        if(searchUser != null && passwordEncoder.matches(password, searchUser.getPassword())) {
             return searchUser;
        }
        return null;
    }
}
