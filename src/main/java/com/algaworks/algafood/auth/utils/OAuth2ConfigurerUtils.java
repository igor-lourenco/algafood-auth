package com.algaworks.algafood.auth.utils;


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

/** Classe utilitária interna usada para recuperar ou criar os beans necessários para os Configurar o Authorization Server OAuth 2.0.
 * Esta classe vem do Authorization Server OAuth2 do Spring Security.*/
@Log4j2
public final class OAuth2ConfigurerUtils {

    private OAuth2ConfigurerUtils() {
    }


/** Esse método é responsável por construir e retornar um OAuth2TokenGenerator, que é o componente central responsável
 *  por gerar todos os tipos de tokens no Spring Authorization Server.*/
    public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getTokenGenerator] componente central responsável por gerar todos os tipos de tokens");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        log.info("Tentando recuperar o OAuth2TokenGenerator do contexto compartilhado do HttpSecurity");
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = httpSecurity.getSharedObject(OAuth2TokenGenerator.class);

        if (tokenGenerator == null) {  // Se ainda não estiver no SharedObject

//          Tenta obter o bean da aplicação (por exemplo, caso tenha sido definido manualmente via @Bean).
            log.info("OAuth2TokenGenerator não encontrado no contexto compartilhado do HttpSecurity, tentando obter algum OAuth2TokenGenerator caso tenha sido definido manualmente via @Bean");
            tokenGenerator = getOptionalBean(httpSecurity, OAuth2TokenGenerator.class);

            if (tokenGenerator == null) { // Se ainda não tiver,

                log.info("Nenhum OAuth2TokenGenerator definido manualmente via @Bean, tentando recuperar um JwtGenerator para criar um novo OAuth2TokenGenerator");
//              Recupera um JwtGenerator - gerador de tokens JWT (Access Token ou ID Token com formato JWT).
                JwtGenerator jwtGenerator = getJwtGenerator(httpSecurity);

//              Gera tokens de acesso (access_token) no formato opaco (não-JWT).
                log.info("Criando um OAuth2AccessTokenGenerator para access_tokens opacos (não-JWT)");
                OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();

//              Recupera um customizador de tokens de acesso
                log.info("Tentando encontrar um customizador de token de acesso");
                OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = getAccessTokenCustomizer(httpSecurity);

                if (accessTokenCustomizer != null) { // Se foi encontrado um customizador de tokens de acesso
                    log.info("Customizador de token de acesso encontrado, adicionando no OAuth2AccessTokenGenerator...");
                    accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer); // Define esse customizador no gerador de token de acesso
                }

//              Gera tokens de refresh (refresh_token)
                log.info("Criando um OAuth2RefreshTokenGenerator para refresh_tokens");
                OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

                if (jwtGenerator != null) { // Se foi encontrado um JwtGenerator, gerador de tokens JWT
//                  Adiciona JwtGenerator encontrado no delegador de geradores de token
                    log.info("OAuth2TokenGenerator encontrado, adicionando no delegador de geradores de token o JwtGenerator, OAuth2AccessTokenGenerator e OAuth2RefreshTokenGenerator");
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
                } else {
//                  Cria o delegador de geradores de token sem o JwtGenerator
                    log.info("OAuth2TokenGenerator não encontrado, adicionando no delegador de geradores de token apenas o OAuth2AccessTokenGenerator e OAuth2RefreshTokenGenerator");
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(accessTokenGenerator, refreshTokenGenerator);
                }
            }

//          Armazena no SharedObject(contexto compartilhado) no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        }

        log.info(">>> FINALIZANDO [getTokenGenerator]");
        return tokenGenerator;
    }



/**  Esse método retorna um JwtGenerator - gerador de JWTs no contexto de segurança do Spring Security*/
    private static JwtGenerator getJwtGenerator(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getJwtGenerator] para obter componente responsável por gerar token JWT completo(Monta o token com os claims, headers, data de expiração, etc.)");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        log.info("Tentando recuperar o JwtGenerator do contexto compartilhado do HttpSecurity");
        JwtGenerator jwtGenerator = httpSecurity.getSharedObject(JwtGenerator.class);

        if (jwtGenerator == null) { // Se ainda não estiver no SharedObject

//          Tenta obter um JwtEncoder, que é o componente responsável por codificar (assinar) o JWT
            log.info("JwtGenerator não encontrado no contexto compartilhado do HttpSecurity, tentando obter um JwtEncoder");
            JwtEncoder jwtEncoder = getJwtEncoder(httpSecurity);

            if (jwtEncoder != null) { // se o JwtEncoder foi encontrado

                log.info("JwtEncoder não encontrado, gerando um novo JwtGenerator com o JwtEncoder encontrado...");
                jwtGenerator = new JwtGenerator(jwtEncoder); // É criado um novo JwtGenerator.

//              Busca um customizador para personalizar o conteúdo do JWT antes de ser codificado (claims, headers, etc)
                log.info("Tentando recuperar um customizador para personalizar o conteúdo do JWT antes de ser codificado");
                OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(httpSecurity);

                if (jwtCustomizer != null) { // Se o customizador for encontrado
                    log.info("Customizador de token encontrado, configurando o customizador no JwtGenerator...");
                    jwtGenerator.setJwtCustomizer(jwtCustomizer); // É configurado no JwtGenerator
                }else{
                    log.info("Customizador não encontrado...");
                }

//              Armazena o JwtGenerator como SharedObject(contexto compartilhado) no HttpSecurity, para futuras chamadas.
                httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
            }
        }

        log.info(">>> FINALIZANDO [getJwtGenerator] ");
//      Retorna o JwtGenerator
        return jwtGenerator;
    }



/**  Esse método tenta obter (ou criar, se necessário) uma instância de JwtEncoder, que é o componente responsável por gerar (codificar) JWTs */
    private static JwtEncoder getJwtEncoder(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getJwtEncoder] para obter componente responsável por codificar (assinar) o JWT - Serializa os dados(headers + claims), aplica a assinatura (ex: HMAC, RSA, etc.), e gera a string final do JWT)");

        log.info("Tentando recuperar o JwtEncoder do contexto compartilhado do HttpSecurity");
//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        JwtEncoder jwtEncoder = httpSecurity.getSharedObject(JwtEncoder.class);

        if (jwtEncoder == null) { // Se ainda não estiver no SharedObject

            log.info("JwtEncoder não do contexto compartilhado do HttpSecurity, buscando no ApplicationContext do HttpSecurity");
//          Tenta buscar um JwtEncoder como bean no ApplicationContext
            jwtEncoder = getOptionalBean(httpSecurity, JwtEncoder.class);

            if (jwtEncoder == null) { // Se ainda não encontrar,

//              Tenta obter a fonte de chaves criptográficas (JWK) por exemplo, é nesse momento que tenta obter o nosso JWKSource implementado em JwtConfig
                log.info("JwtEncoder não encontrado, buscando par de chaves criptográficas (JWK) para criar um JwtEncoder...");
                JWKSource<SecurityContext> jwkSource = getJwkSource(httpSecurity);

                if (jwkSource != null) { // se encontrar, cria um novo NimbusJwtEncoder usando o JWKSource
                    log.info("Instânciando um NimbusJwtEncoder que implementa o JwtEncoder com o par de chaves criptográficas encontrado...");
                    jwtEncoder = new NimbusJwtEncoder(jwkSource);
                }
            }
            if (jwtEncoder != null) { // Se conseguiu um encoder (de qualquer forma), registra no contexto compartilhado para futuras chamadas
                httpSecurity.setSharedObject(JwtEncoder.class, jwtEncoder);
            }
        }

        log.info(">>> FINALIZANDO [getJwtEncoder]");
        return jwtEncoder;
    }



/** Esse método tenta obter a fonte de chaves criptográficas (JWK) usada para assinar e verificar tokens JWT,
    por exemplo, o nosso par de chaves implementado no JwtConfig */
    static JWKSource<SecurityContext> getJwkSource(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getJwkSource] para obter a fonte de chaves criptográficas (JWK)");

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
        log.info(">>> FINALIZANDO [getJwkSource] :: {}", jwkSource);
        return jwkSource;
    }



/** Esse método recupera um customizador de tokens de acesso (usado para construir os claims) usado em tokens não-JWT ex: tokens opacos via introspecção */
    private static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> getAccessTokenCustomizer(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getAccessTokenCustomizer] para buscar o customizador de token de acesso");

//      Cria uma representação de tipo genérico ResolvableType para: OAuth2TokenCustomizer<OAuth2TokenClaimsContext>
        ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, OAuth2TokenClaimsContext.class);

//      Tenta recuperar o bean
        OAuth2TokenCustomizer<OAuth2TokenClaimsContext> optionalBean = getOptionalBean(httpSecurity, type);

        if(optionalBean == null){
            log.info(">>> FINALIZANDO [getAccessTokenCustomizer] :: null");
            return null;
        }
        log.info(">>> FINALIZANDO [getAccessTokenCustomizer] :: {}", optionalBean.getClass().getSimpleName());
        return optionalBean;
    }



/** Esse método recupera um OAuth2TokenCustomizer específico para personalizar tokens JWT
    (é chamado para modificar dinamicamente os dados (incluindo headers, claims, etc.) do token JWT antes que ele seja codificado pelo JwtEncoder. */
    private static OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getJwtCustomizer] para buscar o customizador de token JWT");

//      Cria uma representação de tipo genérico ResolvableType para: OAuth2TokenCustomizer<JwtEncodingContext>
        ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);

//      Tenta recuperar o bean, por exemplo, o JwtConfig implementado na aplicação usado para configurar os tokens JWT
        OAuth2TokenCustomizer<JwtEncodingContext> optionalBean = getOptionalBean(httpSecurity, type);

        if(optionalBean == null){
            log.info(">>> FINALIZANDO [getJwtCustomizer] :: null");
            return null;
        }
        log.info(">>> Finalizando [getJwtCustomizer] :: {}", optionalBean.getClass().getTypeName());
        return optionalBean;
    }



/**  Esse método retorna a configuração do Authorization Server, ou seja, um objeto do tipo AuthorizationServerSettings*/
    static AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getAuthorizationServerSettings] para recuperar o AuthorizationServerSettings do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);

        if (authorizationServerSettings == null) { // se ainda não estiver no SharedObject

//          Tenta buscar diretamente do ApplicationContext, se não encontrar ou tiver mais de um bean compatível o próprio método getBean() lança exception
            authorizationServerSettings = getBean(httpSecurity, AuthorizationServerSettings.class);

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }

        log.info(">>> FINALIZANDO [getAuthorizationServerSettings]" );
        return authorizationServerSettings;
    }



/** Tenta pegar um único bean do tipo 'T' genérico do contexto do Spring Security (ApplicationContext) caso tenha sido definido manualmente via @Bean
 *  Mas lança exceção se houver mais de um bean do mesmo tipo ou se não existir nenhum do mesmo tipo*/
    static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
        return httpSecurity.getSharedObject(ApplicationContext.class).getBean(type);
    }



/** Tenta pegar um único bean do tipo 'T' genérico específico obrigatório usando o ResolvableType no contexto do Spring (ApplicationContext)*/
    static <T> T getBean(HttpSecurity httpSecurity, ResolvableType type) {
        log.info(">>> INICIANDO [getBean] para recuperar o bean do contexto do Spring (ApplicationContext) :: {}",
            type.getGeneric(0).resolve());

//      Usa o SharedObject para pegar o contexto atual do Spring Security, caso tenha sido definido manualmente via @Bean
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);

//      Obtém todos os nomes de beans compatíveis com o tipo ResolvableType vindo como parâmetro, assim é mais poderoso do que Class<T> porque lida com tipos genéricos.
        String[] names = context.getBeanNamesForType(type);

        if (names.length == 1) { // se existir exatamente 1 bean compatível
            log.info(">>> FINALIZANDO [getBean] :: {}", (T) context.getBean(names[0]).getClass().getSimpleName());
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



/** Tenta pegar um único bean do tipo 'T' genérico do contexto do Spring (ApplicationContext) caso tenha sido definido manualmente via @Bean
 * sem lançar exceção se ele não existir, mas lança exceção se houver mais de um bean do mesmo tipo.*/
    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        log.info(">>> INICIANDO [getOptionalBean] para recuperar o bean do contexto do Spring (ApplicationContext) :: {}", type.getSimpleName());

        Map<String, T> beansMap = BeanFactoryUtils
            .beansOfTypeIncludingAncestors( //  Busca todos os beans do tipo T (incluindo beans definidos nos contextos "pais")
            httpSecurity.getSharedObject(ApplicationContext.class) // Usa o SharedObject para pegar o contexto atual do Spring Security, caso tenha sido definido manualmente via @Bean
                , type);

//      Se encontrar mais de um bean, lança uma exceção, isso impede ambiguidade
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                "Expected single matching bean of type '" + type.getName() + "' but found " +
                    beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }

        log.info(">>> FINALIZANDO [getOptionalBean] :: {}", beansMap);

//      Retorna o único bean encontrado, ou null se não houver nenhum.
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }



/** Tenta pegar um único bean do tipo 'T' genérico específico usando o ResolvableType no contexto do Spring (ApplicationContext) caso tenha sido definido manualmente via @Bean
 *  Diferente do metódo getOptionalBean acima, esse método usa o 'ResolvableType' que representa tipos com generics em tempo de execução
 *  e resolve beans e tipos que usam generics com precisão */
    static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
        log.info(">>> INICIANDO [getOptionalBean] específico para recuperar o bean do contexto do Spring (ApplicationContext) :: {}",
            type.getGeneric(0).resolve());

//      Usa o SharedObject para pegar o contexto atual do Spring Security, caso tenha sido definido manualmente via @Bean
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);

//      Obtém todos os nomes de beans compatíveis com o tipo ResolvableType vindo como parâmetro, assim é mais poderoso do que Class<T> porque lida com tipos genéricos.
        String[] names = context.getBeanNamesForType(type);

//      Se houver mais de um bean do tipo, lança exceção.
        if (names.length > 1) {
            throw new NoUniqueBeanDefinitionException(type, names);
        }

//      Retorna o único bean, se existir, ou null
        if(names.length == 1){
            log.info(">>> FINALIZANDO [getOptionalBean] específico :: {}", (T) context.getBean(names[0]).getClass().getSimpleName());
            return (T) context.getBean(names[0]);
        } else {
            log.info(">>> FINALIZANDO [getOptionalBean] específico :: null");
            return null;
        }
//        return names.length == 1 ? (T) context.getBean(names[0]) : null;
    }



    // Esse método pega o bean do tipo RegisteredClientRepository a partir do contexto de segurança (HttpSecurity).
    static RegisteredClientRepository getRegisteredClientRepository(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getRegisteredClientRepository] para recuperar o RegisteredClientRepository do contexto de segurança");

//      Tenta recuperar objeto compartilhado SharedObject(é como uma espécie de "cache local" dentro do HttpSecurity usado para reaproveitar configurações e componentes)
        RegisteredClientRepository registeredClientRepository = httpSecurity.getSharedObject(RegisteredClientRepository.class);

        if (registeredClientRepository == null) { // se ainda não estiver no SharedObject

//          Busca diretamente no contexto do Spring (ApplicationContext) usando um método auxiliar getBean()
            registeredClientRepository = getBean(httpSecurity, RegisteredClientRepository.class);

//          Armazena o resultado como SharedObject no HttpSecurity, para futuras chamadas.
            httpSecurity.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }

        log.info(">>> FINALIZANDO [getRegisteredClientRepository]");
        return registeredClientRepository;
    }

/** Esse método recupera ou cria uma instância de OAuth2AuthorizationService, responsável por armazenar, recuperar e remover autorizações e tokens */
    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getAuthorizationService] para recuperar o OAuth2AuthorizationService do contexto de segurança");

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

        log.info(">>> FINALIZANDO [getAuthorizationService]");
        return authorizationService;
    }

/**  Esse método recupera ou cria uma instância de OAuth2AuthorizationConsentService, usada no fluxo de consentimento do OAuth 2.0 (authorization_code flow)*/
    static OAuth2AuthorizationConsentService getAuthorizationConsentService(HttpSecurity httpSecurity) {
        log.info(">>> INICIANDO [getAuthorizationConsentService] para recuperar o OAuth2AuthorizationConsentService do contexto de segurança");

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

        log.info(">>> FINALIZANDO [getAuthorizationConsentService]");
        return authorizationConsentService;
    }
}