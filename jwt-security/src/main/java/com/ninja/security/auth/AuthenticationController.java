package com.ninja.security.auth;

import java.io.IOException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	
	
	private final AuthenticationService authenticationService;

	@PostMapping("register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
		
		return ResponseEntity.ok(authenticationService.register(request));	
	}
	
	@PostMapping("authenticate")
	public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
		
		return ResponseEntity.ok(authenticationService.authenticate(request));
	}
	
	@PostMapping("refresh-token")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws StreamWriteException, DatabindException, IOException {
		authenticationService.refreshToken(request, response);
	}
}
