package com.hansjoerg.coloringbook;

import com.hansjoerg.coloringbook.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.websocket.servlet.WebSocketServletAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication(exclude = {
        WebSocketServletAutoConfiguration.class,
        SecurityAutoConfiguration.class
})
@EnableConfigurationProperties(AppProperties.class)
public class SpringColoringbookApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringColoringbookApplication.class, args);
	}
}
