package rikkei.academy.service.user;

import rikkei.academy.model.User;

import java.util.Optional;

public interface IUserService {
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByUsername(String username);

    User save(User user);
}
