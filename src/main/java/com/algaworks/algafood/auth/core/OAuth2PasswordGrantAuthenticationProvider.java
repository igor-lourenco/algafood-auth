package com.algaworks.algafood.auth.core;


import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.*;
import java.util.stream.Collectors;

import static com.algaworks.algafood.auth.core.OAuth2PasswordGrantAuthenticationConverter.PASSWORD_GRANT_TYPE;
import static com.algaworks.algafood.auth.core.OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI;


/** {@link AuthenticationProvider} implementation for the OAuth 2.0 Resource Owner Password Credentials Grant. */
@Log4j2
public class OAuth2PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType("password");
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;


    public OAuth2PasswordGrantAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder, OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // informações do usuário passado no parâmetro(por exemplo, o username e password)
        OAuth2PasswordGrantAuthenticationTokenModel passwordGrantAuthenticationToken = (OAuth2PasswordGrantAuthenticationTokenModel) authentication;

        // garante que o cliente esteja autenticado
        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient((Authentication) passwordGrantAuthenticationToken.getPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // se o cliente não estiver registrado ou não for compatível com -> grant_type password (tipo de concessão de senha)
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(passwordGrantAuthenticationToken.getGrantType())) {
            log.info("Cliente não registrado ou grant_type não compatível");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Set<String> authorizedScopes = Collections.emptySet();

        // pega os scopes passados no parâmetro
        if (CollectionUtils.isNotEmpty(passwordGrantAuthenticationToken.getScopes())) {
            for (String requestedScope : passwordGrantAuthenticationToken.getScopes()) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            }
            authorizedScopes = new LinkedHashSet<>(passwordGrantAuthenticationToken.getScopes());
        }

        log.info("Verificando se o usuário existe e se suas credenciais são válidas");
        String providedUsername = passwordGrantAuthenticationToken.getUsername();
        String providedPassword = passwordGrantAuthenticationToken.getPassword();

        UserDetails userDetails = this.userDetailsService.loadUserByUsername(providedUsername);
        if (!this.passwordEncoder.matches(providedPassword, userDetails.getPassword())) {
            log.info("Senha inválida");
            throw new OAuth2AuthenticationException("Invalid resource owner credentials");
        }

        log.info("Adicionando as lista de Authorities");
        passwordGrantAuthenticationToken.getAuthorities().addAll(userDetails.getAuthorities());

        Map<String, Object> tokenMetadata = new HashMap<>();
        tokenMetadata.put("username", userDetails.getUsername());
        tokenMetadata.put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        if (CollectionUtils.isNotEmpty(authorizedScopes)) {
            tokenMetadata.put("scopes", authorizedScopes);
        }

        log.info("Gerando token de acesso");

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(passwordGrantAuthenticationToken)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(PASSWORD_GRANT_TYPE);

        OAuth2TokenContext tokenContext =((DefaultOAuth2TokenContext.Builder) tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN)).build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            log.error("O gerador de tokens falhou ao gerar o token de acesso");
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,"The token generator failed to generate the access token.", ACCESS_TOKEN_REQUEST_ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(userDetails.getUsername())
            .authorizationGrantType(PASSWORD_GRANT_TYPE)
            .token(accessToken, (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenMetadata))
            .build();

        log.info("Gerando refresh token");

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
            tokenContext = ((DefaultOAuth2TokenContext.Builder)tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN)).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                log.error("O gerador de tokens falhou ao gerar o refresh token");
                OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the refresh token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                throw new OAuth2AuthenticationException(error);
            }

            refreshToken = (OAuth2RefreshToken)generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, accessToken);

        log.info("Salvando authorization");
        authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordGrantAuthenticationTokenModel.class.isAssignableFrom(authentication);
    }
}