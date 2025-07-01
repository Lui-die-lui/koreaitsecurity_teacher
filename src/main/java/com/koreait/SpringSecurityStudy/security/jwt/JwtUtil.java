package com.koreait.SpringSecurityStudy.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    private final Key KEY;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateAccessToken(String id) {
        return Jwts.builder()
                .subject("AccessToken") //토큰의 용도를 설명하는 식별자 역할
                .id(id) //토큰에 고유한 식별자를 부여(사용자 ID, 이메일) => 나중에 토큰 무효화나 사용자 조회할때 사용
                .expiration(new Date(new Date().getTime() + (1000L * 60L * 60L * 24L * 30L)))// 토큰의 만료기간
                //현재 시간 기준으로 30일 뒤까지 유효하다
                //1000L = 1초를 밀리초
                //60 * 60 * 24 * 30 => 30일
                .signWith(KEY)//토큰에 서명을 적용
                .compact();//설정한 JWT 내용을 바탕으로 최종적으로 문자열 형태의 JWT생성
    }
    // 이메일 인증
    public String generateMailVerifyToken(String id) {
        return Jwts.builder()
                .subject("VerifyToken")
                .id(id)
                .expiration(new Date(new Date().getTime() + (1000L * 60L * 3L)))// 토큰의 만료기간 1초 60번 3번 = 3분
                .signWith(KEY)
                .compact();
    }

    public boolean isBearer(String token) {
        if (token == null) {
            return false;
        }
        if (!token.startsWith("Bearer ")) {
            return false;
        }
        return true;
    }

    public String removeBearer(String bearerToken) {
        return bearerToken.replaceFirst("Bearer ", "");
    }

    //Claims : JWT의 Payload영역, 사용자 정보, 만료일자 등 담겨있음
    //JwtException : 토큰이 잘못되어있을 경우 (위변조, 만료 등) 발생하는 예외
    public Claims getClaims(String token) throws JwtException {
        JwtParserBuilder jwtParserBuilder = Jwts.parser();
        //Jwts.parser()는 JwtParserBuilder 객체를 반환
        //JWT 파서를 구성할 수 있는 빌더 (parser 설정 작업을 체이닝으로 가능하게 함)
        jwtParserBuilder.setSigningKey(KEY);//토큰의 서명을 검증하기 위해 비밀키 설정
        JwtParser jwtParser = jwtParserBuilder.build();//설정이 완료된 파서를 빌드해서 최종 JwtParser 객체 생성
        return jwtParser.parseClaimsJws(token).getBody();//순수 Claims JWT를 파싱
    }

}
