package lecture.springbootsecurity.repository;

import lecture.springbootsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    UserEntity findByEmail(String email); // 이메일로 계정 찾을 수 있게 됨.

    // 존재하냐에 대한 메소드 하나 더 만들 수 있음.
    Boolean existsByEmail(String email); // 이메일로 존재하는 지 검사해서 boolean 값으로 return

    UserEntity findByEmailAndPassword(String email, String password);

}
