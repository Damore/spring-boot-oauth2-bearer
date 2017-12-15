package br.com.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.oauth.model.Usuario;

public interface UsuarioRepository extends MongoRepository<Usuario, String> {

	Usuario findById(String id);

	Usuario findByEmailAndCpf(String email, String cpf);
}
