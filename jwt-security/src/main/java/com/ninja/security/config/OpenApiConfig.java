package com.ninja.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
		info = @Info(
			contact = @Contact(
					name = "Soe Moe Htet",
					email = "kohtet@gmail.com",
					url = "https://xyz.com"
			),
			description = "OpenApi documentation for Spring Security",
			title = "OpenApi Specification - Ko Htet",
			version = "1.0",
			license = @License(
					name = "MIT License",
					url= "https://opensource.org/license/mit/"
			),
			termsOfService = "Terms of Service"
		),
		servers = {
				@Server(
					description = "LOCAL ENV",
					url = "http://localhost:8080"
				),
				@Server(
					description = "PROD ENV",
					url = "https://xyz.com"
				)
		}, 
		security = {
				@SecurityRequirement(
						name = "bearerAuth"
				)
		}
)

@SecurityScheme(
		name = "bearerAuth",
		description = "JWT Authentication Description",
		scheme = "bearer",
		type = SecuritySchemeType.HTTP,
		bearerFormat = "JWT",
		in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {

}
