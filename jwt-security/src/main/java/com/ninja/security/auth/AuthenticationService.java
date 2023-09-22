package com.ninja.security.auth;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ninja.security.config.JwtService;
import com.ninja.security.entity.Role;
import com.ninja.security.entity.User;
import com.ninja.security.entity.UserRepository;
import com.ninja.security.token.Token;
import com.ninja.security.token.TokenRepository;
import com.ninja.security.token.TokenType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	
	private final PasswordEncoder passwordEncoder;
	private final UserRepository userRepository;
	private final TokenRepository tokenRepository;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
	public AuthenticationResponse register(RegisterRequest request) {
		// Create Registered User
		var user = User.builder()
				.firstName(request.getFirstname())
				.lastName(request.getLastname())
				.email(request.getEmail())
				.password(passwordEncoder.encode(request.getPassword()))
				.role(Role.USER)
				.build();
		
		// Save Registered User to Database
		var savedUser = userRepository.save(user);
		
		// Generate JWT token using user(UserDetails)
		String jwt = jwtService.generateToken(user);
		
		// Generate JWT Refresh Token using user(UserDetails)
		String refreshToken = jwtService.generateRefreshToken(user);
		
		// Save Access Token
		saveUserToken(savedUser, jwt);
		
		return AuthenticationResponse.builder()
				.accessToken(jwt)
				.refreshToken(refreshToken)
				.build();
	}
	

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		
		// If Authentication Success
		var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
		
		// Generate JWT Token
		var jwt = jwtService.generateToken(user);
		
		// Generate Refresh Token
		var refreshToken = jwtService.generateRefreshToken(user);
		
		// Before adding new generated token to database, need to revoke and expire all previous tokens
		revokeAllUserTokens(user);
		
		// After revoke all previous tokens, Save New Access Token
		saveUserToken(user, jwt);
		
		return AuthenticationResponse.builder()
				.accessToken(jwt)
				.refreshToken(refreshToken)
				.build();
	}
	
	private void saveUserToken(User user, String jwtToken) {
		var token = Token.builder()
				.user(user)
				.token(jwtToken)
				.tokenType(TokenType.BEARER)
				.expired(false)
				.revoked(false)
				.build();
		tokenRepository.save(token);
	}
	
	private void revokeAllUserTokens(User user) {
		var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
		if (validUserTokens.isEmpty()) {
			return;
		}
		validUserTokens.forEach(token -> {
			token.setExpired(true);
			token.setRevoked(true);
		});
		tokenRepository.saveAll(validUserTokens);
	}
	
	// when client request 'Access Token' using 'Refresh Token'
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws StreamWriteException, DatabindException, IOException {
		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		final String refreshToken;
		final String userEmail;
		
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return;
		}
		
		refreshToken = authHeader.substring(7);
		userEmail = jwtService.extractUsername(refreshToken);
		
		if (userEmail != null) {
			var user = this.userRepository.findByEmail(userEmail).orElseThrow();
			
			if (jwtService.isTokenValid(refreshToken, user)) {
				var accessToken = jwtService.generateToken(user);
				revokeAllUserTokens(user);
				saveUserToken(user, accessToken);
				
				var authResponse = AuthenticationResponse.builder()
						.accessToken(accessToken)
						.refreshToken(refreshToken)
						.build();
				
				new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
			}
		}
	}

}
