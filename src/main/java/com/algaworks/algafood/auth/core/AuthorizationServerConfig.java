package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.properties.AlgafoodSecurityProperties;
import com.algaworks.algafood.auth.services.JdbcOAuth2AuthorizationQueryService;
import com.algaworks.algafood.auth.services.OAuth2AuthorizationQueryService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;

/**
 * Essa classe é responsável por configurar o servidor de autorização OAuth2, de como os clientes se autenticam e
 * obtêm tokens de acesso.
 */
@Configuration
public class AuthorizationServerConfig {


    @Bean // Aplica as configurações de segurança do OAuth2 ao HttpSecurity
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authFilterChain(HttpSecurity http
        , UserDetailsService userDetailsService
        , PasswordEncoder passwordEncoder
        , OAuth2AuthorizationService authorizationService) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


//      https://gist.github.com/akuma8/2eb244b796f3d3506956207997fb290f
//      Recupera o nosso OAuth2TokenGenerator customizado (que pode gerar JWTs, access tokens, refresh tokens etc.).
        OAuth2TokenGenerator<?> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(http);

//      Esse converter transforma a requisição /oauth2/token com grant_type=password em um Authentication customizado.
        var converter = new OAuth2PasswordGrantAuthenticationConverter();

//      Esse provider é a nossa implementação customizada para autenticar o usuário e o cliente, gerar os tokens (access, refresh) e salvar a autorização no banco de dados
        var provider = new OAuth2PasswordGrantAuthenticationProvider(userDetailsService, passwordEncoder, authorizationService, tokenGenerator);

//      Adicionando o suporte ao fluxo de senha (password grant) no Authorization Server do Spring Security de forma customizada
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint ->
            tokenEndpoint
                .accessTokenRequestConverter(converter) // Adicionando a nossa implementação do AuthenticationConverter (para ler a requisição);
                .authenticationProvider(provider) // Adicionando a nossa implementação do AuthenticationProvider (para validar e emitir tokens).
                .authenticationProvider(new OAuth2PasswordGrantRefreshTokenAuthenticationProvider(authorizationService, tokenGenerator))
        );


        authorizationServerConfigurer.authorizationEndpoint(customizer ->
            customizer.consentPage("/oauth2/consent")); // página de consentimento

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.securityMatcher(endpointsMatcher)
            .authorizeHttpRequests((authorizeRequests) -> {
                authorizeRequests.anyRequest().authenticated();
            }).csrf((csrf) -> {
                csrf.ignoringRequestMatchers(new RequestMatcher[]{endpointsMatcher});
            })
            .formLogin(Customizer.withDefaults())
            .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
                httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
            }).apply(authorizationServerConfigurer);


        // Para personalizar a página de login implementada no WebMvcSecurityConfig
        return http.formLogin(customizer -> customizer.loginPage("/login")).build();
    }


    @Bean // Define uma SecurityFilterChain default
    public SecurityFilterChain defaultFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.formLogin(Customizer.withDefaults())
            .csrf().disable().cors(); // Desativa proteção contra CSRF (Cross-Site Request Forgery) porque o ataque de CSRF geralmente depende de um navegador do usuário e de cookies de autenticação

        return httpSecurity.build();
    }


    @Bean // Define as configurações do provedor de identidade, incluindo a URL do emissor (issuer)
    public AuthorizationServerSettings authorizationServerSettings(AlgafoodSecurityProperties properties) {
        return AuthorizationServerSettings.builder()
            .issuer(properties.getProviderUrl())
            .build();
    }

    @Bean // Regista cliente OAuth2
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder, JdbcOperations jdbcOperations) {

        RegisteredClient algafoodClientCredentialsTokenOpaco = clienteClientCredentialsUsandoTokenOpaco(passwordEncoder);
        RegisteredClient algafoodClientCredentialsTokenJWT = clienteClientCredentialsUsandoTokenJWT(passwordEncoder);
        RegisteredClient algafoodAuthorizationCodeTokenJWT = clienteAuthorizationCodeUsandoTokenJWT(passwordEncoder);
        RegisteredClient algafoodPasswordTokenJWT = clientePasswordUsandoTokenJWT(passwordEncoder); // password flow depreciado


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
        registeredClientRepository.save(algafoodPasswordTokenJWT);

        return registeredClientRepository;

    }

    @Bean
    // Configura serviço de autorização OAuth2 baseado em JDBC para armazenar e gerenciar autorizações de clientes.
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository); // sem usar a implementação customizada
        // return new CustomOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    private static RegisteredClient clienteClientCredentialsUsandoTokenOpaco(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("1")
            .clientId("algafood-web-client-credentials-token-opaco")
            .clientName("Algafood web client_credentials token opaco")
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
            .clientName("Algafood web client_credentials token jwt")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // fluxo client credentials
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // implementa o refresh token para esse cliente

            .scope("READ")

            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Token JWT
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .reuseRefreshTokens(false) // refresh token não pode ser reutilizado
                .refreshTokenTimeToLive(Duration.ofDays(1)) // tempo de vida do refresh token
                .build())

            .build();
    }


    private static RegisteredClient clienteAuthorizationCodeUsandoTokenJWT(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("3")
            .clientId("algafood-web-authorization-code-token-jwt")
            .clientName("Algafood web authorization_code token jwt")
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
                .requireAuthorizationConsent(true) // Não obrigatório aparecer a tela de consentimento
                .build())

            .build();
    }


    // O Fluxo Passowrd Flow foi depreciado pelo OAuth 2.1
    private static RegisteredClient clientePasswordUsandoTokenJWT(PasswordEncoder passwordEncoder) {
        return RegisteredClient
            .withId("4")
            .clientId("algafood-web-password-token-jwt")
            .clientName("Algafood web password_flow token jwt")
            .clientSecret(passwordEncoder.encode("web123"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD) // fluxo password
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // implementa o refresh token para esse cliente

            .scope("READ")
            .scope("WRITE")

            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Token JWT
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .reuseRefreshTokens(false) // refresh token não pode ser reutilizado
                .refreshTokenTimeToLive(Duration.ofDays(1)) // tempo de vida do refresh token
                .build())

            .build();
    }

    @Bean
    // Configura serviço de autorização OAuth2 baseado em JDBC para armazenar as autorizações de consentimento dos clientes autorizados pelos usuarios.
    public OAuth2AuthorizationConsentService consentService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
//        return new InMemoryOAuth2AuthorizationConsentService();
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }


    //  Configura o nosso próprio bean customizado para consultar as autorizações OAuth2 armazenadas em um banco de dados usando JDBC.
//  Obs: Como o JdbcOperations já existe no contexto como um bean, automaticamente o Spring passa uma instância válida no parâmetro.
    @Bean
    public OAuth2AuthorizationQueryService oAuth2AuthorizationQueryService(JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
        return new JdbcOAuth2AuthorizationQueryService(jdbcOperations, repository);
    }

    @Bean // Define um bean de PasswordEncoder que usa BCryptPasswordEncoder para codificar senhas.
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


