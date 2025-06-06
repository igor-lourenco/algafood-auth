package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import com.algaworks.algafood.auth.utils.OAuth2AuthenticationProviderUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.Set;

import static com.algaworks.algafood.auth.core.OAuth2PasswordGrantAuthenticationConverter.PASSWORD_GRANT_TYPE;

@Log4j2
public class OAuth2PasswordGrantRefreshTokenAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public OAuth2PasswordGrantRefreshTokenAuthenticationProvider(
        OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {

        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication = (OAuth2RefreshTokenAuthenticationToken)authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
            .getAuthenticatedClientElseThrowInvalidClient((Authentication) refreshTokenAuthentication.getPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        log.info("Cliente registrado encontrado: {}", registeredClient.getClientId());

        log.info("Buscando authorization com o refresh_token: {}", refreshTokenAuthentication.getRefreshToken());
        OAuth2Authorization authorization = this.authorizationService.findByToken(refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        log.info("Authorization encontrado");

        if (authorization == null) {
            log.error("Authorization não encontrado para esse refresh token: {}", refreshTokenAuthentication.getRefreshToken());
            throw new OAuth2AuthenticationException("invalid_grant");
        }

        if (!authorization.getAuthorizationGrantType().equals(PASSWORD_GRANT_TYPE)) {
            log.error("Authorization Grant Type não é do tipo PASSWORD_GRANT_TYPE: {}", authorization.getAuthorizationGrantType().getValue());
            throw new OAuth2AuthenticationException("invalid_grant");
        }

        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            log.error("Cliente registrado: {} não é responsável pela authorization registrado no banco de dados: {}"
                , registeredClient.getId(), authorization.getRegisteredClientId());

            throw new OAuth2AuthenticationException("invalid_client");
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            log.error("Cliente registrado não tem o grant_type refresh token: {}", registeredClient.getClientId());
            throw new OAuth2AuthenticationException("unauthorized_client");
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();

        if (!refreshToken.isActive()) {
            log.error("Refresh token expirado: {}", refreshToken.getToken().getTokenValue());
            throw new OAuth2AuthenticationException("invalid_grant");
        }

        Set<String> scopes = refreshTokenAuthentication.getScopes(); //  scopes solicitados durante o uso do refresh token.
        Set<String> authorizedScopes = authorization.getAuthorizedScopes(); // scopes originalmente autorizados quando o usuário autenticou pela primeira vez.
        if (!authorizedScopes.containsAll(scopes)) {
            log.error("Ciente tentou obter um scope que não foi previamente autorizado pelo usuário que autenticou na primeira vez.");
            throw new OAuth2AuthenticationException("invalid_scope");
        }

        log.info("Parâmetros de solicitação de token validados");

        if (scopes.isEmpty()) { // se o scope do refresh token for vazio, vai ser o mesmo scope já autorizados pelo usuario na primeira vez
            scopes = authorizedScopes;
        }

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal( (Authentication) authorization.getAttribute(Principal.class.getName()))
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorization(authorization)
            .authorizedScopes(scopes)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrant(refreshTokenAuthentication);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
            .attribute(Principal.class.getName(), // para salvar o Principal com os mesmo dados do authorization salvo no banco de dados
                 createOAuth2PasswordGrantAuthenticationTokenModel(authorization, clientPrincipal)); // attributes

        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the access token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
            throw new OAuth2AuthenticationException(error);
        }

        log.info("Token de acesso gerado com sucesso...");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

        log.info("Preparando os metadados que serão associados ao Authorization e salvar no banco de dados...");
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) -> {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor)generatedAccessToken).getClaims());
                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            });
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        OAuth2RefreshToken currentRefreshToken = (OAuth2RefreshToken)refreshToken.getToken();
        if (!registeredClient.getTokenSettings().isReuseRefreshTokens()) {
            tokenContext = ((DefaultOAuth2TokenContext.Builder)tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN)).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the refresh token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                throw new OAuth2AuthenticationException(error);
            }

            currentRefreshToken = (OAuth2RefreshToken)generatedRefreshToken;
            authorizationBuilder.refreshToken(currentRefreshToken);

        }

        log.info("Refresh token gerado com sucesso...");

        authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);
        log.info("Salvando authorization");
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, currentRefreshToken);
    }

    private static Authentication createOAuth2PasswordGrantAuthenticationTokenModel(OAuth2Authorization authorization, Authentication clientPrincipal) {
        return new OAuth2PasswordGrantAuthenticationTokenModel(
            authorization.getPrincipalName(),
            "",
            clientPrincipal,
            authorization.getAuthorizedScopes(),
            ((Authentication) authorization.getAttribute(Principal.class.getName())).getAuthorities()
        );
    }

    // Indica que essa classe autentica os token do tipo - OAuth2RefreshTokenAuthenticationToken
    public boolean supports(Class<?> authentication) {
        return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
