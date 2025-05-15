package com.algaworks.algafood.auth.core.utils;


import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import com.algaworks.algafood.auth.utils.OAuth2AuthenticationProviderUtils;
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

import static com.algaworks.algafood.auth.utils.OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI;
import static com.algaworks.algafood.auth.core.utils.OAuth2PasswordGrantAuthenticationConverter.PASSWORD_GRANT_TYPE;


/** {@link AuthenticationProvider} implementation for the OAuth 2.0 Resource Owner Password Credentials Grant. */
@Log4j2
public class OAuth2PasswordGrantAuthenticationProvider implements AuthenticationProvider {
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


        passwordGrantAuthenticationToken.getAuthorities().addAll(userDetails.getAuthorities());

        log.info("Gerando token de acesso");
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(passwordGrantAuthenticationToken)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(PASSWORD_GRANT_TYPE)
            .authorizationGrant(passwordGrantAuthenticationToken)
            .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ACCESS_TOKEN_REQUEST_ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());



        if (log.isDebugEnabled()) {
            log.debug("Creating authorization");
        }

        Map<String, Object> tokenMetadata = new HashMap<>();
        tokenMetadata.put("username", userDetails.getUsername());
        tokenMetadata.put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        if (CollectionUtils.isNotEmpty(authorizedScopes)) {
            tokenMetadata.put("scopes", authorizedScopes);
        }

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(userDetails.getUsername())
            .authorizationGrantType(PASSWORD_GRANT_TYPE)
            .token(accessToken, (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenMetadata))
            .build();

        if (log.isDebugEnabled()) {
            log.debug("Saving authorization");
        }

        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordGrantAuthenticationTokenModel.class.isAssignableFrom(authentication);
    }
}