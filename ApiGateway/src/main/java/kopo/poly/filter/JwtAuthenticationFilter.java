package kopo.poly.filter;

import jakarta.servlet.annotation.WebFilter;
import java.util.Optional;
import kopo.poly.dto.TokenDTO;
import kopo.poly.jwt.JwtStatus;
import kopo.poly.jwt.JwtTokenProvider;
import kopo.poly.jwt.JwtTokenType;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 쿠키에 저장된 JWT 토큰 삭제할 구조 정의
     *
     * @param tokenName 토큰 이름
     * @param 쿠키        구조
     */

    private ResponseCookie deleteTokenCookie(String tokenName) {

        log.info(this.getClass().getName() + "deleteTokenCookie Start!");
        log.info("tokenName : " + tokenName);

        ResponseCookie cookie = ResponseCookie.from(tokenName, "")
                .maxAge(0)
                .build();

        log.info(this.getClass().getName() + "deleteTokenCookie end!");

        return cookie;

    }

    /**
     * 쿠키에 저장할 JWT 구조 정의
     *
     * @param tokenName
     * @param tokenValidTime
     * @param token
     * @return 쿠키 구조
     */
    private ResponseCookie createTokenCookie(String tokenName, long tokenValidTime, String token) {

        log.info(this.getClass().getName() + " createTokenCookies Start!");

        log.info("tokenName :" + tokenName);
        log.info("token :" + token);

        ResponseCookie cookie = ResponseCookie.from(tokenName, token)
                .domain("localhost")
                .path("/")
//                .secure(true)
//                .sameSite("None")
                .maxAge(tokenValidTime)
                .httpOnly(true)
                .build();

        log.info(this.getClass().getName() + " createTokenCookies end!");

        return cookie;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        log.info(this.getClass().getName() + " filter Start!");

        log.info("request :" + request);
        log.info("request :" + request.getPath());

        // 쿠키 or Http 인증헤더에서 Access Token 가져오기
        String accessToken = CmmUtil.nvl(jwtTokenProvider.resolveToken(request,
                JwtTokenType.ACCESS_TOKEN));

        log.info("accessToken : " + accessToken);

        // access token 유효기간 검증하기
        JwtStatus accessTokenStatus = jwtTokenProvider.validateToken(accessToken);

        log.info("accessTokenStatus :" + accessTokenStatus);

        // 유효기간 검증하기
        if (accessTokenStatus == JwtStatus.ACCESS) {

            // 토큰이 유효하면 토큰으로부터 유저 정보를 받아옵니다.
            // 받은 유저 정보 : 아이디의 권한을 SpringSecurity에 저장
            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

            // SecurityContext 에 Authentication 객체를 저장합니다.
            return chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

        } else if (accessTokenStatus == JwtStatus.EXPIRED ||
                accessTokenStatus == JwtStatus.DENIED) {

            // Access Token이 만료되면, RefreshToken 유효한지 체크한
            // RefreshToekn 확인하기
            String refreshToken = CmmUtil.nvl(
                    jwtTokenProvider.resolveToken(request, JwtTokenType.REFRESH_TOKEN));

            // Refresh Token 유효기간 검증하기
            JwtStatus refreshTokenStatus = jwtTokenProvider.validateToken(refreshToken);

            log.info("refreshTokenStatus : " + refreshTokenStatus);

            if (refreshTokenStatus == JwtStatus.ACCESS) {

                TokenDTO rDTO = Optional.ofNullable(jwtTokenProvider.getTokenInfo(refreshToken))
                        .orElseGet(() -> TokenDTO.builder().build());

                String userId = CmmUtil.nvl(rDTO.userId());
                String userRoles = CmmUtil.nvl(rDTO.role());

                log.info("refreshToken userId : " + userId);
                log.info("refreshToken userRoles : " + userRoles);

                String reAccessToken = jwtTokenProvider.createToken(userId, userRoles);

                response.addCookie(this.deleteTokenCookie(accessTokenName));

                response.addCookie(this.createTokenCookie(accessTokenName, accessTokenValidTime,
                        reAccessToken));

                Authentication authentication = jwtTokenProvider.getAuthentication(reAccessToken);

                return chain.filter(exchange)
                        .contextWrite(
                                ReactiveSecurityContextHolder.withAuthentication(authentication));
            } else if (refreshTokenStatus == JwtStatus.EXPIRED) {
                log.info("Refresh Token 만료 - 스프링 시큐리티가 로그인 페이지로 이동 시킴");

            } else {
                log.info("Refresh Token 오류 - 스프링 시큐리티가 로그인 페이지로 이동 시킴");

            }

        }

        log.info(this.getClass().getName() + " filter Start!");

        return chain.filter(exchange);

    }


}
