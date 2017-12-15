package br.com.oauth.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;

import br.com.oauth.service.CustomClientDetailsService;
import br.com.oauth.service.CustomTokenStore;
import br.com.oauth.service.CustomUserDetailsService;

@SpringBootApplication
@ComponentScan({ "br.com.oauth.config", "br.com.oauth.service", "br.com.oauth.repository" })
@EntityScan(basePackages = { "br.com.oauth.model" })
@EnableMongoRepositories(basePackages = { "br.com.oauth.repository" })
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	/**
	 * Criptografia BCryptPasswordEncoder para o password.
	 * 
	 * @return BCryptPasswordEncoder
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public TokenStore tokenStore() {
		CustomTokenStore customTokenStore = new CustomTokenStore();
		return customTokenStore;
	}

	/**
	 * Implementação para autenticação do usuario.
	 * 
	 * @return UserDetailsService
	 */
	@Bean(name = "userDetailsService")
	public UserDetailsService userDetailsService() {
		CustomUserDetailsService customUserDetailsService = new CustomUserDetailsService();
		return customUserDetailsService;
	}

	/**
	 * Implementação para autenticação do sistema.
	 * 
	 * @return ClientDetailsService
	 */
	@Bean
	public ClientDetailsService clientDetailsService() {
		CustomClientDetailsService customClientDetailsService = new CustomClientDetailsService();
		return customClientDetailsService;
	}
}
