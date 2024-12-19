package com.algaworks.algafood.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**  Essa classe configura a segurança da aplicação web em geral, definindo usuários em memória, codificando senhas
  com BCrypt e fornecendo um gerenciador de autenticação.  */
@Configuration
@EnableWebSecurity  //  Habilita a configuração de segurança da web no Spring Security.
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Override // Configura a autenticação do usuário final (Resource Owner)
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication() // Indica que a autenticação será configurada em memória. Os dados dos usuários são definidos diretamente no código e mantidos apenas enquanto a aplicação está em execução.
                .withUser("igor")
                .password(passwordEncoder().encode("123"))
                .roles("ADMIN")
            .and()
                .withUser("joao")
                .password(passwordEncoder().encode("123"))
                .roles("ADMIN");

    }


    @Bean // Define um bean de PasswordEncoder que usa BCryptPasswordEncoder para codificar senhas.
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    @Override //  Define um bean de AuthenticationManager que usa a implementação padrão fornecida pela superclasse.
    protected AuthenticationManager authenticationManager() throws Exception{
        return super.authenticationManager();
    }

}
