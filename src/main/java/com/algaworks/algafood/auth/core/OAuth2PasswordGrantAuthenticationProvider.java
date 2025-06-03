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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
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

import java.lang.reflect.Field;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import static com.algaworks.algafood.auth.core.OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI;
import static com.algaworks.algafood.auth.core.OAuth2PasswordGrantAuthenticationConverter.PASSWORD_GRANT_TYPE;


/** Implementação do OAuth 2.0 para o fluxo: Resource Owner Password Credentials Grant. */
@Log4j2
public class OAuth2PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    private static final String AUTHORIZATION_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
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
        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
            .getAuthenticatedClientElseThrowInvalidClient((Authentication) passwordGrantAuthenticationToken.getPrincipal());

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // se o cliente não estiver registrado ou não for compatível com -> grant_type password (tipo de concessão de senha)
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(passwordGrantAuthenticationToken.getGrantType())) {
            log.info("Cliente não registrado ou grant_type não compatível com 'password'");
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // pega os scopes passados no parâmetro da request e validando se o cliente tem esses scopes
        Set<String> authorizedScopes = Collections.emptySet();

        if (CollectionUtils.isNotEmpty(passwordGrantAuthenticationToken.getScopes())) {
            for (String requestedScope : passwordGrantAuthenticationToken.getScopes()) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    log.error("O client: {}, não tem cadastrado o scope: {}", registeredClient.getClientId(), requestedScope);
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

        log.info("Token de acesso gerado com sucesso...");
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

        log.info("Preparando os metadados que serão associados ao Authorization e salvar no banco de dados...");
        Map<String, Object> tokenMetadata = new HashMap<>();
        tokenMetadata.put("username", userDetails.getUsername());
        tokenMetadata.put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        if (CollectionUtils.isNotEmpty(authorizedScopes)) {
            tokenMetadata.put("scopes", authorizedScopes);
        }


        // Criando Authentication para ser salvo no banco de dados sem as credentials do cliente e usuário
        OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequestWithGrantTypePassword(passwordGrantAuthenticationToken);
        OAuth2ClientAuthenticationToken clientAuthenticated = createOAuth2ClientAuthenticationToken(clientPrincipal);
        Authentication principal = createOAuth2PasswordGrantAuthenticationTokenModel(passwordGrantAuthenticationToken, clientAuthenticated, userDetails);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(userDetails.getUsername()) // principal_name
            .authorizationGrantType(PASSWORD_GRANT_TYPE) // authorization_grant_type
            .authorizedScopes(passwordGrantAuthenticationToken.getScopes()) // authorized_scopes
            .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest) // attributes
            .attribute(Principal.class.getName(), principal) // attributes
            .token(accessToken, (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenMetadata)) //access_token_metadata
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

        log.info("Refresh token gerado com sucesso...");




        authorization = authorizationBuilder.build();
//      authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, accessToken); // não é necessário na geração do token JWT

        log.info("Salvando authorization");
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }



    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordGrantAuthenticationTokenModel.class.isAssignableFrom(authentication);
    }


    private OAuth2AuthorizationRequest createOAuth2AuthorizationRequestWithGrantTypePassword(OAuth2PasswordGrantAuthenticationTokenModel passwordGrantAuthenticationToken){
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
            .scopes(passwordGrantAuthenticationToken.getScopes())
            .authorizationUri(AUTHORIZATION_URI)
            .clientId(passwordGrantAuthenticationToken.getClientId())
            .attributes(add -> add.putAll(Map.of("username", passwordGrantAuthenticationToken.getUsername())))
            .additionalParameters(add -> add.putAll(Map.of("username", passwordGrantAuthenticationToken.getUsername())))
            .build();

        Class<?> aClass = authorizationRequest.getClass();

        try {
            Field authorizationGrantType = aClass.getDeclaredField("authorizationGrantType");
            authorizationGrantType.setAccessible(true);
            authorizationGrantType.set(authorizationRequest, new AuthorizationGrantType("password"));

            Field responseType = aClass.getDeclaredField("responseType");
            responseType.setAccessible(true);
            responseType.set(authorizationRequest, new OAuth2AuthorizationResponseType("password"));

            return authorizationRequest;
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }


    private Authentication createOAuth2PasswordGrantAuthenticationTokenModel(OAuth2PasswordGrantAuthenticationTokenModel passwordGrantAuthenticationToken
        , OAuth2ClientAuthenticationToken clientAuthenticated, UserDetails userDetails) {

        return new OAuth2PasswordGrantAuthenticationTokenModel(
            passwordGrantAuthenticationToken.getUsername(),
            "",
            clientAuthenticated,
            passwordGrantAuthenticationToken.getScopes(),
            userDetails.getAuthorities()
        );

    }


    private OAuth2ClientAuthenticationToken createOAuth2ClientAuthenticationToken(OAuth2ClientAuthenticationToken clientPrincipal) {
        return new OAuth2ClientAuthenticationToken(
            clientPrincipal.getRegisteredClient(),
            clientPrincipal.getClientAuthenticationMethod(),
            null);
    }
}