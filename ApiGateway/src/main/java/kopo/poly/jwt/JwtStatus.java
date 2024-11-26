package kopo.poly.jwt;

public enum JwtStatus {
    ACCESS, // 유요한 토큰
    DENIED, // 유요하지 않은 토큰
    EXPIRED // 만료시간
}
