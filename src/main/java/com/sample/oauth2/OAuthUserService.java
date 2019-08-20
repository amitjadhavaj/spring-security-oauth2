
package com.sample.oauth2;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class OAuthUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	protected final Logger logger = LoggerFactory.getLogger(getClass());

	@Value(value = "${oauth.appname.publicKey}")
	private String key;

	public OAuthUserService() {

	}

	private void verifyAccessToken(String token)
			throws NoSuchAlgorithmException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
			SignatureException, IllegalArgumentException, InvalidKeySpecException {
		key = key.replace("-----BEGIN PUBLIC KEY-----", "");
		key = key.replace("-----END PUBLIC KEY-----", "");
		byte[] byteKey = Base64.getDecoder().decode(key.getBytes());
		X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Claims body = Jwts.parser().setSigningKey(kf.generatePublic(X509publicKey)).parseClaimsJws(token).getBody();
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

		String accessToken = userRequest.getAccessToken().getTokenValue();

		Map<String, Object> map = null;
		try {
			verifyAccessToken(accessToken);
			String jwtBase64 = accessToken.split("\\.")[1];
			String jwtJson = new String(Base64.getDecoder().decode(jwtBase64.getBytes()));
			ObjectMapper mapper = new ObjectMapper();
			map = mapper.readValue(jwtJson, new TypeReference<Map<String, Object>>() {
			});
		} catch (IOException | ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
				| SignatureException | NoSuchAlgorithmException | IllegalArgumentException
				| InvalidKeySpecException e) {
			this.logger.warn("Could not fetch user details: " + e.getClass() + ", " + e.getMessage());

		}

		String authority = "ROLE_USER";
		List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(authority);
		String userNameAttributeName = "user_name";
		return new DefaultOAuth2User(authorities, map, userNameAttributeName);
	}
}