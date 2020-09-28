package com.bz.springboot.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository  extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    // 로그인으로 반환되는 값중 email을 통해 생성된 사용자인지 처음 가입하는 사용자인지 판단.
}
