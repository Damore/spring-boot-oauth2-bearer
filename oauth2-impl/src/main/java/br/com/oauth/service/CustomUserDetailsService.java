package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioService usuarioPainelService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails usuario = null;
		usuario = usuarioPainelService.findById(username);

		if (usuario == null) {
			throw new UsernameNotFoundException("user not found");
		}

		return usuario;
	}

}
