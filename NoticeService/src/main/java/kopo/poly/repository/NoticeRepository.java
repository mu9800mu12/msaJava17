package kopo.poly.repository;

import feign.Param;
import java.util.List;
import kopo.poly.repository.entity.NoticeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface NoticeRepository extends JpaRepository<NoticeEntity, Long> {

    List<NoticeEntity> findAllByOrderByNoticeSeqDesc();

    NoticeEntity findByNoticeSeq(Long noticeSeq);

    @Modifying(clearAutomatically = true)
    @Query(value =
    "UPDATE NOTICE A SET A.READ_CNT = IFNULL(A.READ_CNT, 0) + 1" +
    "WHERE A.NOTICE_SEQ = :noticeSeq",
    nativeQuery = true)
    int updateReadCnt(@Param("noticeSeq") Long noticeSeq);

}
