package com.algaworks.algafood.auth.models;


import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.io.Serial;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static com.algaworks.algafood.auth.core.OAuth2PasswordGrantAuthenticationConverter.PASSWORD_GRANT_TYPE;

/**
 * Token de autenticação para a concessão de credenciais de senha do proprietário do recurso OAuth 2.0.
 */
@Getter
public class OAuth2PasswordGrantAuthenticationTokenModel extends OAuth2AuthorizationGrantAuthenticationToken {
    @Serial
    private static final long serialVersionUID = 7840626509676504832L;
    private final String username;
    private final String password;
    private final String clientId;
    private final Set<String> scopes;
    private final Collection<GrantedAuthority> authorities;


    public OAuth2PasswordGrantAuthenticationTokenModel(String username, String password, Authentication clientPrincipal, Set<String> scopes) {
        super(PASSWORD_GRANT_TYPE, clientPrincipal, null);
        this.password = password;
        this.username = username;
        this.clientId = clientPrincipal.getName();
        this.scopes = scopes;
        this.authorities = AuthorityUtils.NO_AUTHORITIES;
        this.setAuthenticated(true);
    }


    public OAuth2PasswordGrantAuthenticationTokenModel(String username, String password, Authentication clientPrincipal
        , Set<String> scopes, Collection<? extends GrantedAuthority> authorities) {
        super(PASSWORD_GRANT_TYPE, clientPrincipal, null);
        this.username = username;
        this.password = password;
        this.clientId = clientPrincipal.getName();
        this.scopes = scopes;
        this.authorities = Collections.unmodifiableList(new ArrayList(authorities));
        this.setAuthenticated(true);
    }

}