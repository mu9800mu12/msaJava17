package kopo.poly.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Builder;

@Builder
public record UserInfoDTO(
        String userId,
        String userName,
        String password,
        String email,
        String addr1,
        String addr2,
        String regId,
        String regDt,
        String chgId,
        String chgDt,
        String roles
) {

}
