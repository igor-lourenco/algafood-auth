package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.properties.AlgafoodSecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;

/**  Essa classe é responsável por configurar o servidor de autorização OAuth2, de como os clientes se autenticam e
 obtêm tokens de acesso.  */
@Configuration
public class AuthorizationServerConfig {


    @Bean // Aplica as configurações de segurança do OAuth2 ao HttpSecurity
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Para personalizar a página de login implementada no WebMvcSecurityConfig
        return http.formLogin(customizer -> customizer.loginPage("/login")).build();
    }


    @Bean // Define uma SecurityFilterChain default
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
            .authorizeRequests().antMatchers("/oauth2/**").authenticated() // Exige autenticação para todas as requisições da aplicação exceto os endpoints /oauth2/**.
            .and()
            .csrf().disable(); // Desativa proteção contra CSRF (Cross-Site Request Forgery) porque o ataque de CSRF geralmente depende de um navegador do usuário e de cookies de autenticação

        // Para personalizar a página de login implementada no WebMvcSecurityConfig
        return httpSecurity.formLogin(customizer -> customizer.loginPage("/login")).build();
    }


    @Bean // Define as configurações do provedor de identidade, incluindo a URL do emissor (issuer)
    public ProviderSettings providerSettings(AlgafoodSecurityProperties properties) {
        return ProviderSettings.builder()
            .issuer(properties.getProviderUrl())
            .build();
    }

    @Bean // Regista cliente OAuth2
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder, JdbcOperations jdbcOperations) {

        RegisteredClient algafoodClientCredentialsTokenOpaco = clienteClientCredentialsUsandoTokenOpaco(passwordEncoder);
        RegisteredClient algafoodClientCredentialsTokenJWT = clienteClientCredentialsUsandoTokenJWT(passwordEncoder);
        RegisteredClient algafoodAuthorizationCodeTokenJWT = clienteAuthorizationCodeUsandoTokenJWT(passwordEncoder);


        // armazena em memória
//        return new InMemoryRegisteredClientRepository(
//            Arrays.asList(
//                algafoodClientCredentialsTokenOpaco,
//                algafoodClientCredentialsTokenJWT,
//                algafoodAuthorizationCodeTokenJWT));

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);

//     Obs: Inserção dos clientes, se já foi inserido não faz nada
       registeredClientRepository.save(algafoodClientCredentialsTokenOpaco);
       registeredClientRepository.save(algafoodClientCredentialsTokenJWT);
       registeredClientRepository.save(algafoodAuthorizationCodeTokenJWT);

       return registeredClientRepository;

    }

    @Bean // Configura serviço de autorização OAuth2 baseado em JDBC para armazenar e gerenciar autorizações de clientes.
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository); // sem usar a implementação customizada
    // return new CustomOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    private static RegisteredClient clienteClientCredentialsUsandoTokenOpaco(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("1")
            .clientId("algafood-web-client-credentials-token-opaco")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // fluxo client credentials
            .scope("READ")

            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // Token Opaco
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .build())

            .build();
    }


    private static RegisteredClient clienteClientCredentialsUsandoTokenJWT(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("2")
            .clientId("algafood-web-client-credentials-token-jwt")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // fluxo client credentials
            .scope("READ")

            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Token JWT
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .build())

            .build();
    }


    private static RegisteredClient clienteAuthorizationCodeUsandoTokenJWT(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("3")
            .clientId("algafood-web-authorization-code-token-jwt")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // fluxo authorization code
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // implementa o refresh token para esse cliente

            .scope("READ")
            .scope("WRITE")

            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Token JWT
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .reuseRefreshTokens(false) // refresh token não pode ser reutilizado
                .refreshTokenTimeToLive(Duration.ofDays(1)) // tempo de vida do refresh token
                .build())

            .redirectUri("http://127.0.0.1:8080/authorizated") // Endpoint não existe, usado como exemplo
            .redirectUri("http://127.0.0.1:8080/swagger-ui/oauth2-redirect.html") // Endpoint do Swagger caso queira testar dentro da documentação Swagger
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false) // Não obrigatório aparecer a tela de consentimento
                .build())

            .build();
    }


    @Bean // Define um bean de PasswordEncoder que usa BCryptPasswordEncoder para codificar senhas.
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}


