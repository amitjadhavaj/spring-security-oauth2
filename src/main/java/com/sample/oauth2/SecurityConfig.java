package com.sample.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@PropertySource("application-oauth2.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	
    @Override
	public void configure(HttpSecurity http) throws Exception {
    	 http.authorizeRequests()
         .antMatchers("/oauth_login", "/loginFailure", "/")
         .permitAll()
         .anyRequest()
         .authenticated()
         .and()
         .oauth2Login()
         .loginPage("/oauth_login")
         .authorizationEndpoint()
         .baseUri("/oauth2/authorize-client")
         .authorizationRequestRepository(authorizationRequestRepository())
         .and()
         .tokenEndpoint()
         .accessTokenResponseClient(accessTokenResponseClient())
         .and()
         .defaultSuccessUrl("/loginSuccess")
         .failureUrl("/loginFailure");
   /*     http.authorizeRequests()
            .antMatchers("/oauth_login", "/loginFailure", "/")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .oauth2Login()
            .loginPage("/oauth_login")
            .authorizationEndpoint()
            .baseUri("/oauth2/authorize-client")
            .authorizationRequestRepository(authorizationRequestRepository())
            .and()
            .tokenEndpoint()
            .accessTokenResponseClient(accessTokenResponseClient())
            .and()
            .defaultSuccessUrl("/loginSuccess")
            .failureUrl("/loginFailure")
            .userInfoEndpoint()
            .userService(sapOAuthUserService())
            .and().loginPage("/oauth_login").and()
            .logout().logoutSuccessUrl("/oauth_login")
            .logoutSuccessHandler(sapLogoutHandler())
        	.clearAuthentication(true)
			.deleteCookies("__VCAP_ID__","JSESSIONID","X-Uaa-Csrf")
			.invalidateHttpSession(true)
			.permitAll().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.and().csrf()
			.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()); */       
    }
 
    @Bean
	public LogoutHandler sapLogoutHandler() {
		return new LogoutHandler();
	}
    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }
    
    @Bean
    public OAuthUserService sapOAuthUserService() { 
    	return new OAuthUserService();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        return accessTokenResponseClient;
    }
}