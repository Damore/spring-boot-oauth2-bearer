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
import br.com.oauth.service.UsuarioService;



@Component
public class FirstLoad {
	public static void main(String[] args) {
		System.out.println(UUID.randomUUID());
	}

	@Autowired
	private ClientRegistrationService clientRegistrationService;

	@Autowired
	private UsuarioService usuarioPainelService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@PostConstruct
	public void init() {
		this.createSistema();
		this.createUsuario();
	}

	private void createSistema() {
		CustomClientDetails customClientDetailsMobile = createMobileCredentials();
		clientRegistrationService.addClientDetails(customClientDetailsMobile);
	}

	private CustomClientDetails createMobileCredentials() {
		CustomClientDetails customClientDetails = new CustomClientDetails();

		// Configurações Básicas
		customClientDetails.setName("aplicacao");
		customClientDetails.setId("1");
		customClientDetails.setClientSecret(passwordEncoder.encode("b1b4ebac-3b9b-48d5-aa3c-c8778a6f00e7"));
		customClientDetails.setAccessTokenValiditySeconds(31557600);
		customClientDetails.setRefreshTokenValiditySeconds(31557700);

		// Permissão
		List<GrantedAuthority> authorities = new ArrayList<>();

		GrantedAuthority authorityClient = new SimpleGrantedAuthority("ROLE_CLIENT");

		authorities.add(authorityClient);
		customClientDetails.setAuthorities(authorities);

		// Tipos de Autenticação
		Set<String> authorizedGrantTypes = new HashSet<>();
		authorizedGrantTypes.add("password");
		authorizedGrantTypes.add("refresh_token");
		authorizedGrantTypes.add("client_credentials");
		customClientDetails.setAuthorizedGrantTypes(authorizedGrantTypes);

		// Escopos
		Set<String> scope = new HashSet<>();
		scope.add("read");
		scope.add("write");
		customClientDetails.setScope(scope);

		// Pendentes
		// customClientDetails.setAutoApproveScope(autoApproveScope);
		// customClientDetails.setAdditionalInformation(additionalInformation);
		// customClientDetails.setRegisteredRedirectUri(registeredRedirectUri);
		// customClientDetails.setRegisteredRedirectUris(registeredRedirectUri);
		// customClientDetails.setResourceIds(resourceIds);
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
		usuarioPainelService.save(usuarioPainel);
	}

}