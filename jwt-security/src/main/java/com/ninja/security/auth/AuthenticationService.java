package com.ninja.security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ninja.security.config.JwtService;
import com.ninja.security.entity.Role;
import com.ninja.security.entity.User;
import com.ninja.security.entity.UserRepository;
import com.ninja.security.token.Token;
import com.ninja.security.token.TokenRepository;
import com.ninja.security.token.TokenType;

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
		
		// Save Access Token
		saveUserToken(savedUser, jwt);
		
		return AuthenticationResponse.builder()
				.token(jwt)
				.build();
	}
	

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		
		// If Authentication Success
		var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
		
		// Generate JWT Token
		var jwt = jwtService.generateToken(user);
		
		// Save Access Token
		saveUserToken(user, jwt);
		
		return AuthenticationResponse.builder()
				.token(jwt)
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

}
