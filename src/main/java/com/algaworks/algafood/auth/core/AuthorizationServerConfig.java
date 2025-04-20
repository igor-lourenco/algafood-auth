package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.properties.AlgafoodSecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.Arrays;

/**  Essa classe é responsável por configurar o servidor de autorização OAuth2, de como os clientes se autenticam e obtêm tokens de acesso.  */
//@EnableAuthorizationServer // Habilita a configuração do servidor de autorização OAuth2.
@Configuration
public class AuthorizationServerConfig {


    @Bean // Aplica as configurações padrão de segurança do OAuth2 ao HttpSecurity
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        return http.build();
    }


    @Bean // Define as configurações do provedor de identidade, incluindo a URL do emissor (issuer)
    public ProviderSettings providerSettings(AlgafoodSecurityProperties properties) {
        return ProviderSettings.builder()
            .issuer(properties.getProviderUrl())
            .build();
    }

    @Bean // Regista cliente OAuth2
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {

        RegisteredClient algafoodbackend = RegisteredClient
            .withId("1")
            .clientId("algafood-web")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // fluxo client credentials
            .scope("READ")
            .tokenSettings(TokenSettings.builder()

//              .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // Token opaco
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Token JWT

                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .build())
            .build();


        // armazena em memória
        return new InMemoryRegisteredClientRepository(Arrays.asList(algafoodbackend));
    }


    @Bean
    // Configura serviço de autorização OAuth2 baseado em JDBC para armazenar e gerenciar autorizações de clientes.
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository); // sem usar a implementaçã customizada
//        return new CustomOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

}


