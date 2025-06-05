package com.algaworks.algafood.auth.utils;


import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * Métodos utilitários para o OAuth 2.0 {@link AuthenticationProvider}. Esta classe vem do Spring Security OAuth2 Authorization Server.
 */
public final class OAuth2AuthenticationProviderUtils {

    private OAuth2AuthenticationProviderUtils() {
    }


/** Esse método verifica se o Authentication representa um cliente OAuth2 autenticado.
    Se não for, ou se não estiver autenticado, lança uma exception.*/
    public static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;

//      Verifica se o authentication recebido é ou herda de OAuth2ClientAuthenticationToken.
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
//          Faz o cast para OAuth2ClientAuthenticationToken
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication;
        }

//      Se o clientPrincipal não for nulo e estiver autenticado (via isAuthenticated())
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

//      Caso contrário, lança uma exception com o erro padrão invalid_client, conforme definido na especificação OAuth2.
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }


/** Esse método está relacionado ao gerenciamento do ciclo de vida dos tokens OAuth2 (como AccessToken, RefreshToken e AuthorizationCode).
 *  Marca um ou mais tokens como invalidados (invalidated) dentro da instância de OAuth2Authorization.*/
    static <T extends OAuth2Token> OAuth2Authorization invalidate(
        OAuth2Authorization authorization, T token) {

//      Invalidando o token passado como argumento dentro do Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
            .token(token, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

//      Se o token for um RefreshToken, também invalida o AccessToken e o AuthorizationCode (se ainda existir)
        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {

//          Invalidando o Access Token
            authorizationBuilder.token(
                authorization.getAccessToken().getToken(),(metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));


//          Pegando o Authorization Code
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

//          Invalidando o Authorization Code, se ainda estiver presente e válido
            if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                authorizationBuilder.token(
                    authorizationCode.getToken(),(metadata) ->
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
            }
        }

        return authorizationBuilder.build();
    }
}