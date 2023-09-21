package com.ninja.security.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ninja.security.token.TokenRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final TokenRepository tokenRepository;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, 
			@NonNull HttpServletResponse response, 
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		// check 'Authorization' header in request
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		// Authentication with JWT	
		jwt = authHeader.substring(7);
		userEmail = jwtService.extractUsername(jwt);
		
		if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
			
			// JWT Token need to no_expried and no_revoke, either unauthorized access
			var isTokenIsValid = tokenRepository.findByToken(jwt)
					.map(t -> !t.isExpired() && !t.isRevoked())
					.orElse(false);
			
			if (jwtService.isTokenValid(jwt, userDetails) && isTokenIsValid) {
				
				// This constructor should only be used by AuthenticationManager or AuthenticationProvider implementations that are satisfied with 
				// producing a trusted (i.e. isAuthenticated() = true)authentication token.
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				// the WebAuthenticationDetails containing information about the current request
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				// Changes the currently authenticated principal(The currently logged in user), or removes the authentication information.
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}		
		filterChain.doFilter(request, response);		
	}

}
