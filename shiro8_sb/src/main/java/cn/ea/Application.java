package cn.ea;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(basePackages = "cn.ea.mapper")
public class Application {

    /**
     * 实际启动方式：使用maven启动，maven -> 项目 -> Plugins -> spring-boot -> spring-boot:run
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
