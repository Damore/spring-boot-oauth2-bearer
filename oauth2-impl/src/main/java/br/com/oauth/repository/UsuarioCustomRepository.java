package br.com.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.oauth.model.UsuarioCustom;

public interface UsuarioCustomRepository extends MongoRepository<UsuarioCustom, String> {

	UsuarioCustom findById(String id);

	UsuarioCustom findByEmailAndCpf(String email, String cpf);
}
