package com.ninja.security.config;

import static com.ninja.security.entity.Permission.ADMIN_CREATE;
import static com.ninja.security.entity.Permission.ADMIN_DELETE;
import static com.ninja.security.entity.Permission.ADMIN_READ;
import static com.ninja.security.entity.Permission.ADMIN_UPDATE;
import static com.ninja.security.entity.Permission.MANAGER_CREATE;
import static com.ninja.security.entity.Permission.MANAGER_DELETE;
import static com.ninja.security.entity.Permission.MANAGER_READ;
import static com.ninja.security.entity.Permission.MANAGER_UPDATE;
import static com.ninja.security.entity.Role.ADMIN;
import static com.ninja.security.entity.Role.MANAGER;
import static com.ninja.security.entity.Role.USER;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {
	
	private final AuthenticationProvider authenticationProvider;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final LogoutHandler logoutHandler;
	private final LogoutSuccessHandler logoutSuccessHandler;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf().disable()
			.authorizeHttpRequests()
			.requestMatchers(
					"/api/v1/auth/**",
					"/v2/api-docs",
	                "/v3/api-docs",
	                "/v3/api-docs/**",
	                "/swagger-resources",
	                "/swagger-resources/**",
	                "/configuration/ui",
	                "/configuration/security",
	                "/swagger-ui/**",
	                "/webjars/**",
	                "/swagger-ui/index.html"
					).permitAll()
			
			.requestMatchers("/api/v1/demo-controller").hasAnyRole(USER.name(), ADMIN.name(), MANAGER.name())
			
			.requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
			.requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
			.requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
			.requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
			.requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())
			
			/*
			 * .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())
			.requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
			.requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
			.requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
			.requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())
			 */
			
			.anyRequest()
			.authenticated()
			.and()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authenticationProvider(authenticationProvider)
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.logout()
			.logoutUrl("/api/v1/auth/logout")
			.addLogoutHandler(logoutHandler)
			.logoutSuccessHandler(logoutSuccessHandler); // clear SecurityContextHolder and return logoutResponse JSON 
		
		return http.build();
	}

}

/*
 * Explicitly clears the context value from the current thread.
 * 
 * logoutSuccessHandler((request, response, authentication) -> 
				SecurityContextHolder.clearContext())
				
*/				
