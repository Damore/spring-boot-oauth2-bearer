package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UsuarioService usuarioService;
	
	@Autowired
	private UsuarioCustomService usuarioCustomService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails usuario = null;
		usuario = usuarioService.findById(username);

		if (usuario == null) {
			throw new UsernameNotFoundException("user not found");
		}

		return usuario;
	}
	
	public UserDetails loadUserByCustomUsername(String username) throws UsernameNotFoundException {
		UserDetails usuario = null;
		usuario = usuarioCustomService.findById(username);

		if (usuario == null) {
			throw new UsernameNotFoundException("user not found");
		}

		return usuario;
	}

}
