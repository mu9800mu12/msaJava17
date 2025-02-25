package kopo.poly.auth;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.util.CmmUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Slf4j
public record AuthInfo(UserInfoDTO userInfoDTO) implements UserDetails {

    /**
     * 로그인한 사용자의 권한 부여하기
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Set<GrantedAuthority> pSet = new HashSet<>();

        String roles = CmmUtil.nvl(userInfoDTO.roles());

        log.info("getAuthorities / roles :" + roles);

        if(roles.length() > 0) {
            for (String role : roles.split(",")) {
                pSet.add(new SimpleGrantedAuthority(role));
            }
        }

        return pSet;
    }

    /**
     * 사용자의 id를 반환 (unique한 값)
     */
    @Override
    public String getUsername() {
        return CmmUtil.nvl(userInfoDTO.userId());
    }

    /**
     * 사용자의 password를 반환
     */
    @Override
    public String getPassword() {
        return CmmUtil.nvl((userInfoDTO.password()));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // true -> 만료되지 않았음}
    }
    @Override
    public boolean isAccountNonLocked() {
        return true; // true -> 잠금되지 않았음
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // true -> 만료되지 않았음}
    }

    @Override
    public boolean isEnabled() {return true; }// true -> 사용 가능




}
