package rikkei.academy.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;

import java.util.Optional;

public interface IRoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName name);
}
