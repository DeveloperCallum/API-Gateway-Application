package com.beamedcallum.gateway.application.security;

import com.beamedcallum.common.database.UserEntry;
import com.beamedcallum.common.database.UserRepository;
import com.beamedcallum.common.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MySqlDetailsService implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntry> searchResult = userRepository.findById(username);
        searchResult.orElseThrow(() -> new UsernameNotFoundException("Username could not be found"));

        return new User(searchResult.get());
    }
}