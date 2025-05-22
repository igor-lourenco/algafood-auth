package com.algaworks.algafood.auth.core;


import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.StringUtils;

import java.util.Map;

/** Métodos utilitários para os Configuradores OAuth 2.0. Esta classe vem do Authorization Server OAuth2 do Spring Security.*/
@Log4j2
public final class OAuth2ConfigurerUtils {

    private OAuth2ConfigurerUtils() {
    }

// Esse método pega o bean do tipo RegisteredClientRepository a partir do contexto de segurança (HttpSecurity).
    static RegisteredClientRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getRegisteredClientRepository] para recuperar o RegisteredClientRepository do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        RegisteredClientRepository registeredClientRepository = httpSecurity.getSharedObject(RegisteredClientRepository.class);

        if (registeredClientRepository == null) { // se ainda não estiver no SharedObject

//          Busca diretamente no contexto do Spring (ApplicationContext) usando um método auxiliar getBean()
            registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository.class);

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }

        log.info(">>> Finalizando método static [getRegisteredClientRepository]");
        return registeredClientRepository;
    }

//  Esse método recupera ou cria uma instância de OAuth2AuthorizationService, responsável por armazenar, recuperar e remover autorizações e tokens
    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getAuthorizationService] para recuperar o OAuth2AuthorizationService do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);

        if (authorizationService == null) {// se ainda não estiver no SharedObject

//          Tenta buscar no ApplicationContext através do getOptionalBean() - nosso método utilitário interno
            authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);

            if (authorizationService == null) { // Se também não encontrar

//              Cria uma instância do service em memória
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }

        log.info(">>> Finalizando  método static [getAuthorizationService]");
        return authorizationService;
    }

//  Esse método recupera ou cria uma instância de OAuth2AuthorizationConsentService, usada no fluxo de consentimento do OAuth 2.0 (authorization_code flow)
    static OAuth2AuthorizationConsentService getAuthorizationConsentService(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getAuthorizationConsentService] para recuperar o OAuth2AuthorizationConsentService do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        OAuth2AuthorizationConsentService authorizationConsentService = httpSecurity.getSharedObject(OAuth2AuthorizationConsentService.class);

        if (authorizationConsentService == null) { // se ainda não estiver no SharedObject

//          Tenta buscar no ApplicationContext através do getOptionalBean() - nosso método utilitário interno
            authorizationConsentService = getOptionalBean(httpSecurity, OAuth2AuthorizationConsentService.class);

            if (authorizationConsentService == null) {// Se também não encontrar

//              Cria uma instância do service em memória
                authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
            }

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
        }

        log.info(">>> Finalizando  método static [getAuthorizationConsentService]");
        return authorizationConsentService;
    }


    public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {

        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = httpSecurity.getSharedObject(OAuth2TokenGenerator.class);
        if (tokenGenerator == null) {
            tokenGenerator = getOptionalBean(httpSecurity, OAuth2TokenGenerator.class);
            if (tokenGenerator == null) {
                JwtGenerator jwtGenerator = getJwtGenerator(httpSecurity);
                OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
                OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = getAccessTokenCustomizer(httpSecurity);
                if (accessTokenCustomizer != null) {
                    accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
                }
                OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
                if (jwtGenerator != null) {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(
                        jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
                } else {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(
                        accessTokenGenerator, refreshTokenGenerator);
                }
            }
            httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        }
        return tokenGenerator;
    }

    private static JwtGenerator getJwtGenerator(HttpSecurity httpSecurity) {
        JwtGenerator jwtGenerator = httpSecurity.getSharedObject(JwtGenerator.class);
        if (jwtGenerator == null) {
            JwtEncoder jwtEncoder = getJwtEncoder(httpSecurity);
            if (jwtEncoder != null) {
                jwtGenerator = new JwtGenerator(jwtEncoder);
                OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(httpSecurity);
                if (jwtCustomizer != null) {
                    jwtGenerator.setJwtCustomizer(jwtCustomizer);
                }
                httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
            }
        }
        return jwtGenerator;
    }


//  Esse método tenta obter (ou criar, se necessário) uma instância de JwtEncoder, que é o componente responsável por gerar (codificar) JWTs
    private static JwtEncoder getJwtEncoder(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getJwtEncoder] para obter componente responsável por gerar (codificar) JWTs");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        JwtEncoder jwtEncoder = httpSecurity.getSharedObject(JwtEncoder.class);

        if (jwtEncoder == null) { // Se ainda não estiver no SharedObject

//          Tenta buscar um JwtEncoder como bean no ApplicationContext
            jwtEncoder = getOptionalBean(httpSecurity, JwtEncoder.class);

            if (jwtEncoder == null) { // Se ainda não encontrar,
                log.info("Nenhum bean JwtEncoder encontrado, buscando par de chaves criptográficas (JWK)...");
//              Tenta obter a fonte de chaves criptográficas (JWK) por exemplo, é nesse momento que tenta obter o nosso JWKSource implementado em JwtConfig
                JWKSource<SecurityContext> jwkSource = getJwkSource(httpSecurity);

                if (jwkSource != null) { // se encontrar, cria um novo NimbusJwtEncoder usando o JWKSource:
                    log.info("Instânciando um NimbusJwtEncoder com o par de chaves criptográficas encontrado...");
                    jwtEncoder = new NimbusJwtEncoder(jwkSource);
                }
            }
            if (jwtEncoder != null) { // Se conseguiu um encoder (de qualquer forma), registra no contexto compartilhado:
                httpSecurity.setSharedObject(JwtEncoder.class, jwtEncoder);
            }
        }

        log.info(">>> Finalizando método static [getJwtEncoder]");
        return jwtEncoder;
    }



//  Esse método tenta obter a fonte de chaves criptográficas (JWK) usada para assinar e verificar tokens JWT
//  Por exemplo, o nosso par de chaves implementado no JwtConfig
    static JWKSource<SecurityContext> getJwkSource(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getJwkSource] para obter a fonte de chaves criptográficas (JWK)");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        JWKSource<SecurityContext> jwkSource = httpSecurity.getSharedObject(JWKSource.class);

        if (jwkSource == null) {// se ainda não estiver no SharedObject

//          Cria uma representação de tipo genérico ResolvableType para: JWKSource<SecurityContext>
            ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);

//          Usa ResolvableType para buscar um bean com tipo genérico exato JWKSource<SecurityContext> no ApplicationContext.
            jwkSource = getOptionalBean(httpSecurity, type);

            if (jwkSource != null) { // Se encontrar, registra como objeto compartilhado
                httpSecurity.setSharedObject(JWKSource.class, jwkSource);
            }
        }

//      Retorna o bean ou null se não houver:
        log.info(">>> Finalizando método static [getJwkSource] :: {}", jwkSource);
        return jwkSource;
    }



//  Esse método recupera um customizador de tokens de acesso (usado para construir os claims) usado em tokens não-JWT ex: tokens opacos via introspecção
    private static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> getAccessTokenCustomizer(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getAccessTokenCustomizer] para buscar o customizador de token de acesso");

//      Cria uma representação de tipo genérico ResolvableType para: OAuth2TokenCustomizer<OAuth2TokenClaimsContext>
        ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, OAuth2TokenClaimsContext.class);

//      Tenta recuperar o bean
        OAuth2TokenCustomizer<OAuth2TokenClaimsContext> optionalBean = getOptionalBean(httpSecurity, type);

        if(optionalBean == null){
            log.info("Finalizando método static [getAccessTokenCustomizer] :: null");
            return null;
        }
        log.info(">>> Finalizando método static [getAccessTokenCustomizer] :: {}", optionalBean.getClass().getSimpleName());
        return optionalBean;
    }



//  Esse método recupera um OAuth2TokenCustomizer específico para personalizar tokens JWT (é chamado para transformar os claims em JWT (incluindo headers, assinatura, etc.)
    private static OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getJwtCustomizer] para buscar o customizador de token JWT");

//      Cria uma representação de tipo genérico ResolvableType para: OAuth2TokenCustomizer<JwtEncodingContext>
        ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);

//      Tenta recuperar o bean, por exemplo, o JwtConfig implementado na aplicação usado para configurar os tokens JWT
        OAuth2TokenCustomizer<JwtEncodingContext> optionalBean = getOptionalBean(httpSecurity, type);

        if(optionalBean == null){
            log.info("Finalizando método static [getJwtCustomizer] :: null");
            return null;
        }
        log.info(">>> Finalizando método static [getJwtCustomizer] :: {}", optionalBean.getClass().getTypeName());
        return optionalBean;
    }



//  Esse método retorna a configuração do Authorization Server, ou seja, um objeto do tipo AuthorizationServerSettings.
    static AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        log.info(">>> Iniciando método static [getAuthorizationServerSettings] para recuperar o AuthorizationServerSettings do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);

        if (authorizationServerSettings == null) { // se ainda não estiver no SharedObject

//          Tenta buscar diretamente do ApplicationContext, se não encontrar ou tiver mais de um bean compatível o próprio método getBean() lança exception
            authorizationServerSettings = getBean(httpSecurity, AuthorizationServerSettings.class);

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }

        log.info(">>> Iniciando método static [getAuthorizationServerSettings]" );
        return authorizationServerSettings;
    }



/** Tenta pegar um único bean do tipo 'T' genérico do contexto do Spring Security (ApplicationContext)
 *  Mas lança exceção se houver mais de um bean do mesmo tipo ou se não existir nenhum do mesmo tipo*/
    static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
        return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
    }



/** Tenta pegar um único bean do tipo 'T' genérico específico obrigatório usando o ResolvableType no contexto do Spring (ApplicationContext)*/
    static <T> T getBean(HttpSecurity httpSecurity, ResolvableType type) {
        log.info(">>> Iniciando método static [getBean] para recuperar o bean do contexto do Spring (ApplicationContext) :: {}",
            type.getGeneric(0).resolve());

//      Usa o SharedObject para pegar o contexto atual do Spring Security, é o mesmo contexto onde os @Beans estão registrados.
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);

//      Obtém todos os nomes de beans compatíveis com o tipo ResolvableType vindo como parâmetro, assim é mais poderoso do que Class<T> porque lida com tipos genéricos.
        String[] names = context.getBeanNamesForType(type);

        if (names.length == 1) { // se existir exatamente 1 bean compatível
            log.info(">>> Finalizando método static [getBean] :: {}", (T) context.getBean(names[0]).getClass().getSimpleName());
            return (T) context.getBean(names[0]);
        }

        if (names.length > 1) { // se existir mais de 1 bean compatível, Lança exception, pois o método espera apenas um bean único
            log.error("Foi encontrado mais de um bean compatível");
            throw new NoUniqueBeanDefinitionException(type, names);
        }

//      Se não encontrar nenhum bean compatível, lança exception
        log.error("Não foi encontrado nenhum bean compatível");
        throw new NoSuchBeanDefinitionException(type);
    }



/** Tenta pegar um único bean do tipo 'T' genérico do contexto do Spring (ApplicationContext) sem lançar exceção se ele não existir.
 *  Mas lança exceção se houver mais de um bean do mesmo tipo.*/
    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        log.info(">>> Iniciando método static [getOptionalBean] para recuperar o bean do contexto do Spring (ApplicationContext) :: {}", type.getSimpleName());

        Map<String, T> beansMap = BeanFactoryUtils
            .beansOfTypeIncludingAncestors( //  Busca todos os beans do tipo T (incluindo beans definidos nos contextos "pais")
            httpSecurity.getSharedObject(ApplicationContext.class) // Usa o SharedObject para pegar o contexto atual do Spring Security, é o mesmo contexto onde os @Beans estão registrados.
                , type);

//      Se encontrar mais de um bean, lança uma exceção, isso impede ambiguidade
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                "Expected single matching bean of type '" + type.getName() + "' but found " +
                    beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }

        log.info(">>> Finalizando método static [getOptionalBean] :: {}", beansMap);

//      Retorna o único bean encontrado, ou null se não houver nenhum.
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }



/** Tenta pegar um único bean do tipo 'T' genérico específico usando o ResolvableType no contexto do Spring (ApplicationContext)
 *  Diferente do metódo getOptionalBean acima, esse método usa o 'ResolvableType' que representa tipos com generics em tempo de execução
 *  e resolve beans e tipos que usam generics com precisão */
    static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
        log.info(">>> Iniciando método static [getOptionalBean] específico para recuperar o bean do contexto do Spring (ApplicationContext) :: {}",
            type.getGeneric(0).resolve());

//      Usa o SharedObject para pegar o contexto atual do Spring Security, é o mesmo contexto onde os @Beans estão registrados.
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);

//      Obtém todos os nomes de beans compatíveis com o tipo ResolvableType vindo como parâmetro, assim é mais poderoso do que Class<T> porque lida com tipos genéricos.
        String[] names = context.getBeanNamesForType(type);

//      Se houver mais de um bean do tipo, lança exceção.
        if (names.length > 1) {
            throw new NoUniqueBeanDefinitionException(type, names);
        }

//      Retorna o único bean, se existir, ou null
        if(names.length == 1){
            log.info(">>> Finalizando método static [getOptionalBean] específico :: {}", (T) context.getBean(names[0]).getClass().getSimpleName());
            return (T) context.getBean(names[0]);
        } else {
            log.info(">>> Finalizando método static [getOptionalBean] específico :: null");
            return null;
        }
//        return names.length == 1 ? (T) context.getBean(names[0]) : null;
    }

}