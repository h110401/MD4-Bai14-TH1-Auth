package rikkei.academy.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rikkei.academy.model.User;

import java.util.Optional;

public interface IUserRepository extends JpaRepository<User, Long> {
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByUsername(String username);
}
