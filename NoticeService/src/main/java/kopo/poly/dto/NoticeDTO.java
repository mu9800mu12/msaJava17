package kopo.poly.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import kopo.poly.repository.entity.NoticeEntity;
import lombok.Builder;

import java.util.List;

import static java.util.stream.Collectors.toList;

@Builder
@JsonInclude(JsonInclude.Include.NON_DEFAULT)
public record NoticeDTO(

        Long noticeSeq, // 기본키, 순번
        String title, // 제목
        String noticeYn, // 공지글 여부
        String contents, // 글 내용
        String userId, // 작성자
        Long readCnt, // 조회수
        String regId, // 등록자 아이디
        String regDt, // 등록일
        String chgId, // 수정자 아이디
        String chgDt, // 수정일
        String userName, // 등록자명
        String readCntYn // 조회수 증가여부

) {


}