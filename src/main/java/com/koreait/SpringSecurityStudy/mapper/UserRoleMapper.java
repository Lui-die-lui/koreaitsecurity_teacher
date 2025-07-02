package com.koreait.SpringSecurityStudy.mapper;

import com.koreait.SpringSecurityStudy.entity.UserRole;
import org.apache.ibatis.annotations.Mapper;

import java.util.Optional;

@Mapper
public interface UserRoleMapper {
    int insert(UserRole userRole);
    Optional<UserRole> getUserRoleByUserIdAndRoleId(Integer userId, Integer roleId);
    int updateRoleId(Integer userId, Integer userRoleId);
}
