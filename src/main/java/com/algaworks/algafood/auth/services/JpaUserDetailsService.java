package com.algaworks.algafood.auth.services;

import com.algaworks.algafood.auth.models.UsuarioModel;
import com.algaworks.algafood.auth.repositories.UsuarioRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

// Spring Security vai usar essa classe que implementa a interface UserDetailsService para carregar dados específicos do usuário.
@Service
@Slf4j
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository repository;

    @Transactional(readOnly = true) // para evitar que o entityManager seja fechado antes de pegas as permissões do usuário
    @Override // Recupera informações do usuário com base no nome de usuário fornecido. Esses dados são então utilizados para realizar a autenticação.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info(">>> Carregando informações do usuário com base no email de usuário fornecido [loadUserByUsername] :: " + username);

        UsuarioModel usuarioModel = repository.findByEmail(username)
            .orElseThrow(() -> {
                log.warn("Usuário não encontrado com o email informado: " + username);
                throw new UsernameNotFoundException("Usuário não encontrado com o email informado: " + username);
            });

        log.info(">>> Informações carregadas [loadUserByUsername] :: " + username);
        return new AuthUser(usuarioModel, getAuthorities(usuarioModel));
    }

/** Retorna coleção dos nomes das permissões do usuario autenticado */
    private Collection<? extends GrantedAuthority> getAuthorities(UsuarioModel usuarioModel){

        return usuarioModel.getGrupos().stream()
            .flatMap(grupoModel -> grupoModel.getPermissoes().stream())
            .map(permissaoModel -> new SimpleGrantedAuthority(permissaoModel.getNome().toUpperCase()))
            .collect(Collectors.toSet());

    }
}
