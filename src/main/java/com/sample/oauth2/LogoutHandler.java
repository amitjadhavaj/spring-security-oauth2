package com.sample.oauth2;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class LogoutHandler implements LogoutSuccessHandler {
	protected final Logger logger = LoggerFactory.getLogger(getClass());

	@Value("https://*****.com/logout.do")
	String logoutUrl;


	@Override
	public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			Authentication authentication) throws IOException, ServletException {
		Object details = authentication.getDetails();
		if (details !=null && details.getClass() !=null && details.getClass().isAssignableFrom(OAuth2AuthenticationDetails.class)) {

			String accessToken = ((OAuth2AuthenticationDetails) details).getTokenValue();
			logger.debug("token: {}", accessToken);

			RestTemplate restTemplate = new RestTemplate();

			MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
			params.add("access_token", accessToken);

			HttpHeaders headers = new HttpHeaders();
			headers.add("Authorization", "bearer " + accessToken);
			HttpEntity<String> request = new HttpEntity(params, headers);
			HttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
			HttpMessageConverter stringHttpMessageConverternew = new StringHttpMessageConverter();
			restTemplate.setMessageConverters(Arrays
					.asList(new HttpMessageConverter[] { formHttpMessageConverter, stringHttpMessageConverternew }));
			try {
				ResponseEntity<String> response = restTemplate.exchange(logoutUrl, HttpMethod.GET, request,
						String.class);
				response.getStatusCode();
				response.getBody();

			} catch (HttpClientErrorException e) {
				e.printStackTrace();
				logger.error(
						"HttpClientErrorException invalidating token with SSO authorization server. response.status code: {}, server URL: {}",
						e.getStatusCode(), logoutUrl);
			}
		}

	}
}