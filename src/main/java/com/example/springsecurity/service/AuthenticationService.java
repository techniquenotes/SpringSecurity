package com.example.springsecurity.service;

import com.example.springsecurity.dao.UserMapper;
import com.example.springsecurity.dto.LoginUserDto;
import com.example.springsecurity.dto.RegisterUserDto;
import com.example.springsecurity.entity.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class AuthenticationService {
    private final UserMapper userMapper;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserMapper userMapper,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userMapper = userMapper;
        this.passwordEncoder = passwordEncoder;
    }

    public User signup(RegisterUserDto input) {
        User user = new User();
        user.setId(UUID.randomUUID().toString().replace("-", ""));
        user.setUserName(input.getUserName());
        user.setPassword(passwordEncoder.encode(input.getPassword()));
        userMapper.insertUser(user);
        //返回当前用户
        return userMapper.findByUserName(user.getUsername()).get();
    }

    public User authenticate(LoginUserDto input) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getUserName(),
                        input.getPassword()
                )
        );
        //认证成功，返回当前用户，用于生成Token
        return userMapper.findByUserName(input.getUserName())
                .orElseThrow();
    }
}
