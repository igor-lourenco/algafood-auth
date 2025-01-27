package com.algaworks.algafood.auth.services;

import com.algaworks.algafood.auth.models.UsuarioModel;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collections;

// Extend a classe User que implementa UserDetailsService que gerencia as informações de autenticação e autorização do usuário.
// Assim a gente pode usar as configurações já criadas pelo User e adicionamos os nossos atributos e implementação
@Getter
public class AuthUser extends User implements Serializable {
    private static final long serialVersionUID = 1L;

    private String fullName;
//  private String email;


    public AuthUser(UsuarioModel model) {
        super(model.getEmail(), model.getSenha(), Collections.emptyList()); // construtor User

        this.fullName = model.getNome();
    }
}
