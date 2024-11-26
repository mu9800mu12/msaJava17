package kopo.poly.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class SwaggerConfig {

    private Info apiInfo() {
        return new Info()
                .title("NoticeService")
                .description("Notice Service Description!")
                .contact(new Contact().name("Prof. ChanWOo Song")
                        .email("mu9800mu12@naver.com")
                        .url("https://www.kopo.ac.kr.kengseo/content.do?menu=1547"))
                .license(new License()
                        .name("한국폴리텍대학 서울 강서캠퍼스 빅데이터과 학생들은 모두 자유롭게 이용가능"))
                .version("1.0.0");
    }

    @Bean
    public OpenAPI openAPI() {return new OpenAPI().components(new Components()).info(apiInfo());}

}
