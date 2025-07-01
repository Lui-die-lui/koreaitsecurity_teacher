package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.dto.SendMailReqDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MailService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JavaMailSender javaMailSender; // 메일보내기 가능

    public ApiRespDto<?> sendMail(SendMailReqDto sendMailReqDto, PrincipalUser principalUser) {
        // 사용자가 토큰을 가지고 있는 경오 - principaluser있음 + 입력한 이메일 있음
        // 그게 일치하는지 확인
        if (!principalUser.getEmail().equals(sendMailReqDto.getEmail())) {
            return new ApiRespDto<>("faild","잘못된 접근입니다.",null);
        }
        // 이메일 있는지 확인
        Optional<User> optionalUser =  userRepository.getUserByEmail(sendMailReqDto.getEmail());

        if (optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed","사용자 정보를 확인해주세요.",null);
        }
        // 통과 한 경우 : 인증이 완료됨

        User user = optionalUser.get();

        boolean hasTempRole = user.getUserRoles().stream()
                .anyMatch(userRole -> userRole.getRoleId() == 3); // userroles 리스트에 3번이 있는지

        if (!hasTempRole) { // 만약 3번이 아니면
            return new ApiRespDto<>("failed", "인증이 필요한 계정이 아닙니다.",null);
        }

        // 로그인 할때 인증 email 만들어줌

        String token = jwtUtil.generateMailVerifyToken(user.getUserId().toString()); // generateAccessToken 에서 string 으로 id를 받음

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail()); // 수신자 이메일
        message.setSubject("이메일 인증 입니다."); // 제목
        message.setText("링크를 클랙 인증을 완료해주세요. : " +
                "http://localhost:8080/mail/verify?verifyToken=" + token); // ?requestparam 값 = 토큰 -> 서버로 받아서 확인 후 임시-> 일반 사용자로 변경

        // 메일 보내줌
        javaMailSender.send(message);

        return new ApiRespDto<>("success","인증 메일이 전송되었습니다. 메일을 확인하세요.", null);


    }
}
