package kopo.poly.auth;

import com.ctc.wstx.util.StringUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.SecretKey;
import kopo.poly.dto.TokenDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.hibernate.annotations.Comment;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@RefreshScope
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.token.creator}")
    private String creator;

    @Value("${jwt.token.access.valid.time}")
    private long accessTokenValidTime;

    @Value("${jwt.token.access.name}")
    private String accessTokenName;

    @Value("${jwt.token.refresh.valid.time}")
    private long refreshTokenValidTime;

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;


    public static final String HEADER_PREFIX = "Bearer"; //Bearer 토큰 사용을 위한 선언 값

    /**
     * JWT 토큰 생성
     */

    public String createToken(String userId, String roles, JwtTokenType tokenType) {
        log.info(this.getClass().getName() + ".create Token Start!");

        log.info("userId :" + userId);

        long validTime = 0;

        if (tokenType == JwtTokenType.ACCESS_TOKEN) {
            validTime = (accessTokenValidTime);

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) {
            validTime = (refreshTokenValidTime);

        }

        Claims claims = Jwts.claims()
                .setIssuer(creator)
                .setSubject(userId);

        claims.put("roles", roles);
        Date now = new Date();

        log.info(this.getClass().getName() + " create Token End");

        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + (validTime * 1000)))
                .signWith(secret, SignatureAlgorithm.HS256)
                .compact();

    }

    /**
     * JWT 토큰에 저장된 값 가져오기
     */

    public TokenDTO getTokenInfo(String token) {
        log.info(this.getClass().getName() + "getTokenInfo Start");

        SecretKey seret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token)
                .getBody();

        String userId = CmmUtil.nvl(claims.getSubject());
        String role = CmmUtil.nvl((String) claims.get("roles"));

        log.info("userId : " + userId);
        log.info("role :" + role);

        TokenDTO rDTO = TokenDTO.builder().userId(userId).role(role).build();

        log.info(this.getClass().getName() + "getTokenInfo ENd");

        return rDTO;
    }

    /**
     * 쿠키 및 인증헤더 저장된 JWT 토큰 가져오기
     */
    public String resolveToken(HttpServletRequest request, JwtTokenType tokenType) {

        log.info(this.getClass().getName() + " resolverToken Start");

        String tokenName = "";

        if (tokenType == JwtTokenType.ACCESS_TOKEN) {
            tokenName = accessTokenName;
        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) {
            tokenName = refreshTokenName;
        }
        String token = "";

        Cookie[] cookies = request.getCookies();



            if (cookies != null) {
                for (Cookie key : request.getCookies()) {
                    log.info("cookies 이름 : " + key.getName());

                    if (key.getName().equals(tokenName)) {
                        token = CmmUtil.nvl(key.getValue());
                        break;
                    }
                }
            }

            if (token.length() == 0) {
                String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);

                log.info("bearerToken :" + bearerToken);
                if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
                    token = bearerToken.substring(7);
                }

                log.info("bearerToken token :" + token);

            }

            log.info(this.getClass().getName() + " resolverToken End");
            return token;


    }
}

