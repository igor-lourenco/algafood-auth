package com.algaworks.algafood.auth.services;

import com.algaworks.algafood.auth.models.UsuarioModel;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;

// Extend a classe User que implementa UserDetailsService que gerencia as informações de autenticação e autorização do usuário.
// Assim a gente pode usar as configurações já criadas pelo User e adicionamos os nossos atributos e implementação
@Getter
public class AuthUser extends User implements Serializable {
    private static final long serialVersionUID = 1L;

    private String fullName;
    private Long userId;


    public AuthUser(UsuarioModel model, Collection<? extends GrantedAuthority> authorities) {
        super(model.getEmail(), model.getSenha(), authorities); // construtor pai User

        this.fullName = model.getNome();
        this.userId = model.getId();
    }
}
