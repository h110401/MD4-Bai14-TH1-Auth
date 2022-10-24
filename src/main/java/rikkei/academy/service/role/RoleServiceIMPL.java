package rikkei.academy.service.role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.repository.IRoleRepository;

import java.util.Optional;

@Service
public class RoleServiceIMPL implements IRoleService {

    @Autowired
    IRoleRepository repository;

    @Override
    public Optional<Role> findByName(RoleName name) {
        return repository.findByName(name);
    }
}
