package com.koreait.SpringSecurityStudy.controller;

import com.koreait.SpringSecurityStudy.dto.SendMailReqDto;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import com.koreait.SpringSecurityStudy.service.MailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller // jsp
@RequestMapping("/mail")
public class MailController {

    @Autowired
    private MailService mailService;

    @PostMapping("/send")
    public ResponseEntity<?> sendEmail(@RequestBody SendMailReqDto sendMailReqDto, @AuthenticationPrincipal PrincipalUser principalUser) {
        return ResponseEntity.ok(mailService.sendMail(sendMailReqDto, principalUser));

    }

    @GetMapping("/verify")
    public String verify(Model model, @RequestParam String verifyToken) { // JSP할거라 스트링
        Map<String, Object> resultMap = mailService.verify(verifyToken);
        model.addAllAttributes(resultMap);
        return "result_page";
    }

}