package br.com.oauth.config;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.stereotype.Component;

import br.com.oauth.model.CustomClientDetails;
import br.com.oauth.model.Usuario;
import br.com.oauth.model.UsuarioCustom;
import br.com.oauth.service.UsuarioCustomService;
import br.com.oauth.service.UsuarioService;



@Component
public class FirstLoad {
	public static void main(String[] args) {
		System.out.println(UUID.randomUUID());
	}

	@Autowired
	private ClientRegistrationService clientRegistrationService;

	@Autowired
	private UsuarioService usuarioService;
	
	@Autowired
	private UsuarioCustomService usuarioCustomService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostConstruct
	public void init() {
		this.createSistema();
		this.createUsuario();
		this.createUsuarioCustom();
	}

	private void createSistema() {
		CustomClientDetails credentialsApp1 = createCredentialsApp1();
		CustomClientDetails credentialsApp2 = createCredentialsApp2();
		clientRegistrationService.addClientDetails(credentialsApp1);
		clientRegistrationService.addClientDetails(credentialsApp2);
	}

	private CustomClientDetails createCredentialsApp1() {
		CustomClientDetails customClientDetails = new CustomClientDetails();

		customClientDetails.setName("aplicacao1");
		customClientDetails.setId("1");
		customClientDetails.setClientSecret(passwordEncoder.encode("b1b4ebac-3b9b-48d5-aa3c-c8778a6f00e7"));
		customClientDetails.setAccessTokenValiditySeconds(900);
		customClientDetails.setRefreshTokenValiditySeconds(1500);

		List<GrantedAuthority> authorities = new ArrayList<>();

		GrantedAuthority authorityClient = new SimpleGrantedAuthority("ROLE_CLIENT");

		authorities.add(authorityClient);
		customClientDetails.setAuthorities(authorities);

		Set<String> authorizedGrantTypes = new HashSet<>();
		authorizedGrantTypes.add("password");
		authorizedGrantTypes.add("refresh_token");
		authorizedGrantTypes.add("client_credentials");
		customClientDetails.setAuthorizedGrantTypes(authorizedGrantTypes);

		Set<String> scope = new HashSet<>();
		scope.add("read");
		scope.add("write");
		customClientDetails.setScope(scope);
		
		return customClientDetails;
	}
	
	private CustomClientDetails createCredentialsApp2() {
		CustomClientDetails customClientDetails = new CustomClientDetails();

		customClientDetails.setName("aplicacao2");
		customClientDetails.setId("2");
		customClientDetails.setClientSecret(passwordEncoder.encode("bf6acd12-e59f-11e7-80c1-9a214cf093ae"));
		customClientDetails.setAccessTokenValiditySeconds(900);
		customClientDetails.setRefreshTokenValiditySeconds(1500);

		List<GrantedAuthority> authorities = new ArrayList<>();

		GrantedAuthority authorityClient = new SimpleGrantedAuthority("ROLE_CLIENT");

		authorities.add(authorityClient);
		customClientDetails.setAuthorities(authorities);

		Set<String> authorizedGrantTypes = new HashSet<>();
		authorizedGrantTypes.add("custom");
		authorizedGrantTypes.add("refresh_token");
		customClientDetails.setAuthorizedGrantTypes(authorizedGrantTypes);

		Set<String> scope = new HashSet<>();
		scope.add("read");
		scope.add("write");
		customClientDetails.setScope(scope);

		return customClientDetails;
	}


	private void createUsuario() {
		Usuario usuarioPainel = new Usuario();
		usuarioPainel.setId("root@100");
		usuarioPainel.setCompradorId(1L);
		usuarioPainel.setNome("ROOT");
		usuarioPainel.setFieldToSort(usuarioPainel.getNome().toLowerCase());
		usuarioPainel.setPassword(passwordEncoder.encode("14785236"));
		usuarioPainel.setCpf("999999999");
		usuarioPainel.setEmail("meuemail@gmail.com");
		usuarioPainel.setAccountNonLocked(true);
		usuarioPainel.setEnabled(true);
		usuarioService.save(usuarioPainel);
	}
	
	private void createUsuarioCustom() {
		UsuarioCustom usuarioPainel = new UsuarioCustom();
		usuarioPainel.setId("meuusuario-123");
		usuarioPainel.setCompradorId(1L);
		usuarioPainel.setNome("usuariocustom");
		usuarioPainel.setFieldToSort(usuarioPainel.getNome().toLowerCase());
		usuarioPainel.setPassword(passwordEncoder.encode("454545"));
		usuarioPainel.setCpf("888888888");
		usuarioPainel.setEmail("meuusuario@gmail.com");
		usuarioPainel.setAccountNonLocked(true);
		usuarioPainel.setEnabled(true);
		usuarioCustomService.save(usuarioPainel);
	}

}