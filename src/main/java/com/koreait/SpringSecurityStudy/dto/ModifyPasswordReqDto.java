package com.koreait.SpringSecurityStudy.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ModifyPasswordReqDto {
    private String oldPassword;
    private String newPassword;
    private String newPasswordCheck;
}
