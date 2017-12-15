package br.com.oauth.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private ClientDetailsService clientDetailsService;
	
	@Autowired
	@Qualifier(value = "authenticationManager")
	private AuthenticationManager authenticationManager;
	
	
	  @Override
	  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
	    security.allowFormAuthenticationForClients().passwordEncoder(passwordEncoder);
	  }

	  /*
	   * Não remover, Configura os Endpoints para o oAuth2
	   */
	  @Override
	  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	    endpoints.authenticationManager(authenticationManager).tokenStore(tokenStore)
	        .userDetailsService(userDetailsService);
	    endpoints.tokenGranter(tokenGranter(endpoints));
	  }

	  private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
	    List<TokenGranter> granters = new ArrayList<TokenGranter>(Arrays.asList(endpoints.getTokenGranter()));
/*	    granters.add(new MyTokenGranter(null, endpoints.getTokenServices(), endpoints.getClientDetailsService(),
	        endpoints.getOAuth2RequestFactory(), "custom"));*/
	    return new CompositeTokenGranter(granters);
	  }

	  /**
	   * * Define como o token e refresh token deve se comportar. * * @return
	   * DefaultTokenServices
	   */
	  @Bean
	  public AuthorizationServerTokenServices defaultAuthorizationServerTokenServices() {
	    DefaultTokenServices tokenServices = new DefaultTokenServices();
	    tokenServices.setTokenStore(tokenStore);
	    tokenServices.setReuseRefreshToken(false);
	    tokenServices.setSupportRefreshToken(true);
	    tokenServices.setClientDetailsService(clientDetailsService);
	    return tokenServices;
	  }
	

}
