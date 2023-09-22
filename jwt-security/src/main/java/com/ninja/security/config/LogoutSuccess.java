package com.ninja.security.config;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class LogoutSuccess implements LogoutSuccessHandler{

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		
		SecurityContextHolder.clearContext();
		
		var logoutResponse = LogoutResponse.builder()
				.httpStatus(HttpStatus.Series.SUCCESSFUL.toString().toLowerCase())
				.message("Logout Successfully")
				.build();
		new ObjectMapper().writeValue(response.getOutputStream(), logoutResponse);
		
	}

}
