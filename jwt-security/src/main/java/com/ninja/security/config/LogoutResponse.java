package com.ninja.security.config;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.ninja.security.auth.AuthenticationResponse;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LogoutResponse {
	
	@JsonProperty("status")
	private String httpStatus;
	@JsonProperty("message")
	private String message;

}
