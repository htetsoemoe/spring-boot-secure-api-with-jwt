package com.ninja.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.ninja.security.auth.AuthenticationService;
import com.ninja.security.auth.RegisterRequest;
import com.ninja.security.entity.Role;

@SpringBootApplication
public class JwtSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecurityApplication.class, args);
	}
	
	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authService) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("admin@ninja.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
			System.out.println("Admin Token: %s".formatted(authService.register(admin).getAccessToken()));
			
			var manager = RegisterRequest.builder()
					.firstname("Manager")
					.lastname("Manager")
					.email("manager@ninja.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			System.out.println("Manager Token: %s".formatted(authService.register(manager).getAccessToken()));
		};
	}

}
