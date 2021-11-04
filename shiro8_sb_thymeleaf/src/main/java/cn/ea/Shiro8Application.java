package cn.ea;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(value = "cn.ea.mapper")
public class Shiro8Application {

    public static void main(String[] args) {
        SpringApplication.run(Shiro8Application.class, args);
    }

}
