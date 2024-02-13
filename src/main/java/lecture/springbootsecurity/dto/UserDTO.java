package lecture.springbootsecurity.dto;

import jakarta.persistence.Column;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserDTO {
    private long id;
    private String username;
    private String email;
    private String password;
}
