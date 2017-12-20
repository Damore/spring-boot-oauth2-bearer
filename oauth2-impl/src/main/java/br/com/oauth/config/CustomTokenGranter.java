package br.com.oauth.config;

import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import br.com.oauth.service.CustomUserDetailsService;

/**
 * A custom {@link TokenGranter} that always grants a token, and does not authenticate users (hence the client has to be
 * trusted to only send authenticated client details).
 * 
 * @author Dave Syer
 *
 */
public class CustomTokenGranter extends AbstractTokenGranter {
	
	private CustomUserDetailsService userDetailsService;
	
	private PasswordEncoder passwordEncoder;
	

	CustomTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService,
			OAuth2RequestFactory requestFactory, String grantType, CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		super(tokenServices, clientDetailsService, requestFactory, grantType);
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		Map<String, String> params = tokenRequest.getRequestParameters();
		String username = params.get("username");
		String password = params.get("password");
		List<GrantedAuthority> authorities = params.containsKey("authorities") ? AuthorityUtils
				.createAuthorityList(OAuth2Utils.parseParameterList(params.get("authorities")).toArray(new String[0]))
				: AuthorityUtils.NO_AUTHORITIES;
		UserDetails loadUserByUsername = userDetailsService.loadUserByCustomUsername(username);
		
		if(!passwordEncoder.matches(password, loadUserByUsername.getPassword())){
			throw new BadCredentialsException("Usuário inexistente ou senha inválida");
		}
		Authentication user = new UsernamePasswordAuthenticationToken(username, password, authorities);
		OAuth2Authentication authentication = new OAuth2Authentication(tokenRequest.createOAuth2Request(client), user);
		return authentication;
	}
}