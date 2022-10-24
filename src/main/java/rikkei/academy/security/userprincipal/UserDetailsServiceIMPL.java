package rikkei.academy.security.userprincipal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import rikkei.academy.model.User;
import rikkei.academy.repository.IUserRepository;

import javax.transaction.Transactional;

@Service
public class UserDetailsServiceIMPL implements UserDetailsService {
    @Autowired
    IUserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("Username not found: " + username));

        return UserPrincipal.build(user);
    }
}
