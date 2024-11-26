package kopo.poly.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import kopo.poly.dto.TokenDTO;
import kopo.poly.util.CmmUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
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

    @Value("${jwt.token.refresh.name}")
    private String refreshTokenName;

    public static final String HEADER_PREFIX = "Bearer "; // 베리어 토큰 사용 선언 값

    /**
     * JWT Access 토큰 생성
     *
     * @param userId 회원 아이디
     * @param roles  회원권한
     * @return 인증 처리한 정보
     */
    public String createToken(String userId, String roles) {
        log.info(this.getClass().getName() + " createToken Start!");

        log.info("userId" + userId);

        Claims claims = Jwts.claims()
                .setIssuer(creator) //JWT 토큰 생성자 기입함
                .setSubject(userId); // 회원아이디 저장 : PK 저장(userId)

        claims.put("rolse", roles);
        Date now = new Date(); // JWT Paylaod에 정의된 기본 옵션 외 정보를 추가 - 사용자 권한 추가

        // 보안키 문자들을 JWT Key 형태로 변경하기
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // 빌더로 토큰 생성
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(
                        new Date(now.getTime() + (accessTokenValidTime * 1000))) // set Expire Time
                .signWith(secret, SignatureAlgorithm.HS256) // 상요할 알고리즘
                .compact();
    }

    /**
     * JWT 토큰(Access Token, Refresh Token)에 저장된 값 가져오기
     *
     * @param token 토큰
     * @return 회원 아이디
     */
    public TokenDTO getTokenInfo(String token) {
        log.info(this.getClass().getName() + "getTokenInfo Start!");

        // 보안키 문자들을 JWT Key 형태로 변경
        SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

        // JWT 토큰 정보
        Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token)
                .getBody();

        String userId = CmmUtil.nvl(claims.getSubject());
        String role = CmmUtil.nvl((String) claims.get("roles")); //LoginService 생성된 토큰의 권한명과 동일

        log.info("userId : " + userId);
        log.info("role : " + role);

        // TokenDTO는 레코드 객체 사용했으니 빌더패턴 적용
        TokenDTO rDTO = TokenDTO.builder().userId(userId).role(role).build();

        log.info(this.getClass().getName() + "getTokenInfo End!");

        return rDTO;

    }

    /**
     * JWT 토큰에서 userId, roles 가져옴 userId와 roles 값을 Spring Securith 인증되었다고 시큐리티 인증 토큰 생성 JWT 토킁느 로그인
     * 되었기에 생성됨 즉, JWT 토큰이 있으면, 로그인이 된 상태
     *
     * @param token 토큰
     * @return 인증 처리한 정보(로그인 성공, 실패)
     */
    public Authentication getAuthentication(String token) {

        log.info(this.getClass().getName() + " getAuthentication start!");

        log.info("getAuthentication :" + token);

        TokenDTO rDTO = getTokenInfo(token); // 토큰에 저장된 정보 가져오기

        String userId = CmmUtil.nvl(rDTO.userId());

        String roles = CmmUtil.nvl(rDTO.role());

        log.info("user_id : " + userId);
        log.info("roles : " + roles);

        Set<GrantedAuthority> pSet = new HashSet<>();
        if (roles.length() > 0) {
            for (String role : roles.split(",")) {
                pSet.add(new SimpleGrantedAuthority(role));

            }
        }

        log.info(this.getClass().getName() + " getAuthentication end!");

        return new UsernamePasswordAuthenticationToken(userId, "", pSet);

    }

    /**
     * 쿠키에 저장 및 HTTP 인증 헤더에 저장된 JWT 토큰 가져오기 쿠키 : 어세스 리프래쉬 토큰 저장됨 HTTP 인증 헤더 : bearer 토큰으로 Access
     * Token만 저장됨
     *
     * @param request
     * @param tokenType
     * @return 쿠키에 저장된 토큰 값
     */
    public String resolveToken(ServerHttpRequest request, JwtTokenType tokenType) {

        log.info(this.getClass().getName() + " resolveToken Start!");

        String token = "";
        String tokenName = "";

        if (tokenType == JwtTokenType.ACCESS_TOKEN) {
            tokenName = accessTokenName;

        } else if (tokenType == JwtTokenType.REFRESH_TOKEN) {
            tokenName = refreshTokenName;
        }

        HttpCookie cookie = request.getCookies().getFirst(tokenName);

        if (cookie != null) {

            token = CmmUtil.nvl(cookie.getValue());

        }

        // Cookies에 토큰이 존재하지 않으면, Baerer 토큰에 값이 있는지 확인함
        if (token.length() == 0) {
            String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            log.info("bearerToken ; " + bearerToken);
            if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)){
                token = bearerToken.substring(7);
            }

            log.info("bearerToken token :" + token);

        }

        log.info(this.getClass().getName() + " resolveToken end!");

        return token;
    }

    /**
     * JWT 토큰 상태 확인
     *
     * @param token
     * @return 상태정보 expired, access, denied
     */
    public JwtStatus validateToken(String token) {

        if (token.length() > 0) {
            try {
                // 보안키 문자들을 JWT Key 형태로 변경하기
                SecretKey secret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));

                // JWT 토큰 정보
                Claims claims = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();

                // 토큰 만료여부 체크
                if (claims.getExpiration().before(new Date())) {
                    return JwtStatus.EXPIRED;

                } else {
                    return JwtStatus.ACCESS;
                }
                } catch (ExpiredJwtException e) {
                    // 만료된 경우에는 refresh token을 확인하기 위해
                    return JwtStatus.EXPIRED;

                } catch (JwtException | IllegalArgumentException e) {
                    log.info("jwtException : {}", e );

                    return JwtStatus.DENIED;
                }


            } else {
                return JwtStatus.DENIED;
            }
        }
    }


