package com.example.springsecurity.dao;

import com.example.springsecurity.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Mapper
public interface UserMapper{
    Optional<User> findByUserName(String userName);

    void insertUser(User user);
}
