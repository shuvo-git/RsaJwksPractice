package com.jobayed.auth_service;

import com.jobayed.auth_service.service.KeyGenService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

	@Bean
	CommandLineRunner run(KeyGenService keyGenService
						  ) {
		return args -> {
			String jwtStr = keyGenService.encryptJwt();
			keyGenService.decryptJwt(jwtStr);
		};
	}

}
