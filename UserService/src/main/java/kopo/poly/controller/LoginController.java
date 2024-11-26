package kopo.poly.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import kopo.poly.auth.AuthInfo;
import kopo.poly.auth.JwtTokenProvider;
import kopo.poly.auth.JwtTokenType;
import kopo.poly.controller.response.CommonResponse;
import kopo.poly.dto.MsgDTO;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@CrossOrigin(origins = {"http://localhost:13000", "http://localhost:14000"},
        allowedHeaders = {"POST, GET"},
        allowCredentials = "true")
@Tag(name = "로그인 관련 API", description = "로그인 관련 API 설명입니다.")
@Slf4j
@RequestMapping(value = "/login")
@RequiredArgsConstructor
@RestController

public class LoginController {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    private final JwtTokenProvider jwtTokenProvider;

    @Operation(summary = "로그인 성공처리  API", description = "로그인 성공처리 API",
            responses = {
                    @ApiResponse(responseCode = "200", description = "OK"),
                    @ApiResponse(responseCode = "404", description = "Page Not Found!"),
            }
    )

    @PostMapping(value = "loginSuccess")
    public MsgDTO loginSuccess(@AuthenticationPrincipal AuthInfo authInfo,
            HttpServletResponse response) {
        log.info(this.getClass().getName() + "loginSuccess Start!");

        UserInfoDTO rDTO = Optional.ofNullable(authInfo.userInfoDTO())
                .orElseGet(() -> UserInfoDTO.builder().build());

        String userId = CmmUtil.nvl(rDTO.userId());
        String userName = CmmUtil.nvl(rDTO.userName());
        String userRoles = CmmUtil.nvl(rDTO.roles());

        log.info("userId : " + userId);
        log.info("userName : " + userName);
        log.info("userRoles : " + userRoles);

        // Access Token 생성
        String accessToken = jwtTokenProvider.createToken(userId, userRoles,
                JwtTokenType.ACCESS_TOKEN);
        log.info("accessToken : " + accessToken);

        ResponseCookie cookie = ResponseCookie.from(accessTokenName, accessToken)
                .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .maxAge(accessTokenValidTime)
                .httpOnly(true)
                .build();

        response.setHeader("Set-Cookie", cookie.toString());

        cookie = null;

        String refreshToken = jwtTokenProvider.createToken(userId, userRoles,
                JwtTokenType.REFRESH_TOKEN);

        log.info("refreshToken :" + refreshToken);

        cookie = ResponseCookie.from(refreshTokenName, refreshToken)
                .domain("localhost")
                .path("/")
                .secure(true)
                .sameSite("None")
                .maxAge(refreshTokenValidTime)
                .httpOnly(true)
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        MsgDTO dto = MsgDTO.builder().result(1).msg(userName + " 님 로그인이 성공하였습니다.").build();

        log.info(this.getClass().getName() + "loginSuccess ENd!");


        return dto;
    }

    @Operation(summary = "로그인 실패처리  API", description = "로그인 실패처리 API",
            responses = {
                    @ApiResponse(responseCode = "200", description = "OK"),
                    @ApiResponse(responseCode = "404", description = "Page Not Found!"),
            }
    )
    @PostMapping(value = "loginFail")
    public ResponseEntity<CommonResponse> loginFail() {

        log.info(this.getClass().getName() + ".loginFail Start!");

        // 결과 메시지 전달하기
        MsgDTO dto = MsgDTO.builder().result(1).msg("로그인이 실패하였습니다.").build();

        log.info(this.getClass().getName() + ".loginFail End!");

        return ResponseEntity.ok(
                CommonResponse.of(HttpStatus.OK, HttpStatus.OK.series().name(), dto));

    }



}
