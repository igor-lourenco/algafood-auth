package com.algaworks.algafood.auth;

// Solução baseada em: https://github.com/spring-projects/spring-security-oauth/pull/675/files

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

public class PkceAuthorizationCodeTokenGranter extends AuthorizationCodeTokenGranter {

    public PkceAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
                                             AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService,
                                             OAuth2RequestFactory requestFactory) {
        super(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
    }


/**  Instancia o getOAuth2Authentication() base e inclui a validação do code_verifier em relação ao code_challenge e ao code_challenge_method.
     Se code_challenge ou code_challenge_method estiverem presentes, mas code_verifier estiver ausente ou for inválido, uma exceção é lançada.*/
    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        OAuth2Authentication authentication = super.getOAuth2Authentication(client, tokenRequest);
        OAuth2Request request = authentication.getOAuth2Request();

        System.out.println("Validando : code_challenge, code_challenge_method e code_verifier");

        String codeChallenge = request.getRequestParameters().get("code_challenge");
        String codeChallengeMethod = request.getRequestParameters().get("code_challenge_method");
        String codeVerifier = request.getRequestParameters().get("code_verifier");

        if (codeChallenge != null || codeChallengeMethod != null) {
            if (codeVerifier == null) {
                throw new InvalidGrantException("Code verifier esperado.");
            }

            if (!validateCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod)) {
                throw new InvalidGrantException(codeVerifier + " não corresponde ao code_verifier esperado.");
            }
        }

        System.out.println("Sucesso na Validação: code_challenge, code_challenge_method e code_verifier");
        return authentication;
    }


/** Valida o code_verifier gerando um code_challenge conforme o método (plain ou S256). Se o método for inválido, uma exceção é lançada. */
    private boolean validateCodeVerifier(String codeVerifier, String codeChallenge, String codeChallengeMethod) {

        String generatedCodeChallenge = null;
        System.out.println("Validando code_challenge: plain ou S256");

        if ("plain".equalsIgnoreCase(codeChallengeMethod)) {
            generatedCodeChallenge = codeVerifier;
        } else if ("s256".equalsIgnoreCase(codeChallengeMethod)) {
            generatedCodeChallenge = generateHashSha256(codeVerifier);
        } else {
            throw new InvalidGrantException(codeChallengeMethod + " não é um challenge method válido.");
        }

        return generatedCodeChallenge.equals(codeChallenge);
    }

    private static String generateHashSha256(String plainText) {
        try {

            System.out.println("Inicio da geração de hash SHA-256 do texto: " + plainText);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

            byte[] hash = messageDigest.digest(Utf8.encode(plainText));
            System.out.println("Hash gerado: " + Arrays.toString(hash));

            String hashEncodeBase64URL = Base64.encodeBase64URLSafeString(hash);
            System.out.println("Codificação do hash em base64_url: " + hashEncodeBase64URL);

            return hashEncodeBase64URL;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}