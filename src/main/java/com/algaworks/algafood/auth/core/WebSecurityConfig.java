package com.algaworks.algafood.auth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

///**  Essa classe configura a segurança da aplicação web em geral, definindo usuários, codificando senhas
//  com BCrypt e fornecendo um gerenciador de autenticação.  */
@Configuration
//@EnableWebSecurity  //  Habilita a configuração de segurança da web no Spring Security.
public class WebSecurityConfig {


    @Bean // Define um bean de PasswordEncoder que usa BCryptPasswordEncoder para codificar senhas.
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
