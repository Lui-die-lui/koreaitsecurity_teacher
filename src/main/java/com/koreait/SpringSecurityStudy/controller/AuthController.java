package com.koreait.SpringSecurityStudy.controller;

import com.koreait.SpringSecurityStudy.dto.ModifyEmailReqDto;
import com.koreait.SpringSecurityStudy.dto.ModifyPasswordReqDto;
import com.koreait.SpringSecurityStudy.dto.SigninReqDto;
import com.koreait.SpringSecurityStudy.dto.SignupReqDto;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import com.koreait.SpringSecurityStudy.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok("test");
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupReqDto signupReqDto) {
        return ResponseEntity.ok(authService.addUser(signupReqDto));
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody SigninReqDto signinReqDto) {
        return ResponseEntity.ok(authService.signin(signinReqDto));
    }

    @GetMapping("/principal")
    public ResponseEntity<?> getPrincipal() {
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication());
    }

    @PostMapping("/{userId}")
    public ResponseEntity<?> modifyEmail(@PathVariable Integer userId, @RequestBody ModifyEmailReqDto modifyEmailReqDto) {
        return ResponseEntity.ok(authService.modifyEmail(userId, modifyEmailReqDto));
    }

    @PostMapping("/password/{userId}")
    public ResponseEntity<?> modifyPassword(
            @PathVariable Integer userId,
            @RequestBody ModifyPasswordReqDto modifyPasswordReqDto,
            @AuthenticationPrincipal PrincipalUser principalUser
            ) {
        if(!userId.equals(principalUser.getUserId())) {
            return ResponseEntity.badRequest().body("본인의 계정만 변경이 가능합니다.");
        }
        return ResponseEntity.ok(authService.modifyPassword(modifyPasswordReqDto, principalUser));
    }

}
