# Fluxo Resource Owner Password Credentials

O Resource Owner Password Credentials (fluxo de senha do proprietário do recurso) solicita que o Resource Owner(usuário) forneça suas credenciais (nome de usuário/e-mail/telefone e senha) junto com as credencias do Client(por exemplo uma aplicação web) para gerar um Acess Token. Como as credenciais são enviadas para o backend e podem ser armazenadas para uso futuro antes de serem trocadas por um Access Token, é de extrema importância que o aplicativo seja absolutamente confiável com essas informações.

## Fluxo de Autenticação

* O Resource Owner faz a requisição para o Client com suas credenciais, e o Client encaminha as credenciais do usuário junto com as credenciais do próprio Client codificada em Base64 para o servidor de autorização:

```
curl --location -X POST 'http://localhost:8081/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic YWxnYWZvb2Qtd2ViOndlYjEyMw==' \
--data-urlencode 'username=igor' \
--data-urlencode 'password=123' \
--data-urlencode 'grant_type=password'
```

![Fluxo_0](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_0.png)

##
* O Servidor de autorização valida as credenciais e retorna o Access Token(e opcionalmente um refresh token) com um tempo válido determinado pelo servidor de autorização:


```
{
    "access_token": "b56755c1-55d4-46e0-9bdf-4903de1a646d",
    "token_type": "bearer",
    "expires_in": 14399,
    "scope": "write read"
}
```

![Fluxo_1](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_1.png)

##
* Após receber o token, o Client pode utilizá-lo para acessar as APIs desejadas do Resource Server:
  
![Fluxo_2](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_2.png)



## Fluxo de Autenticação usando o Refresh Token

* O Resource Owner faz a requisição para o Client com suas credenciais, e o Client encaminha as credenciais do usuário junto com as credenciais do próprio Client codificada em Base64 para o servidor de autorização:

```
curl --location -X POST 'http://localhost:8081/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic YWxnYWZvb2Qtd2ViOndlYjEyMw==' \
--data-urlencode 'username=igor' \
--data-urlencode 'password=123' \
--data-urlencode 'grant_type=password'
```

![Fluxo_0](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_0.png)

##
* O Servidor de autorização valida as credenciais e retorna o Access Token e um Refresh Token com um tempo válido determinado:


```
{
    "access_token": "b56755c1-55d4-46e0-9bdf-4903de1a646d",
    "token_type": "bearer",
    "refresh_token": "ccb77e0d-e2d7-4f49-827b-2d4ec3d655c0",
    "expires_in": 14399,
    "scope": "write read"
}
```

![Fluxo_3](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_3.png)


##
* Depois de um certo tempo determinado pelo servidor de autorização o Access Token é expirado:

![Fluxo_4](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_4.png)


##
* O Client pode fazer uma nova solicitação de Access Token usando o Refresh Token em vez de usar novamente as credencias do Resource Owner:

```
curl --location -X POST 'http://localhost:8081/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic YWxnYWZvb2Qtd2ViOndlYjEyMw==' \
--data-urlencode 'refresh_token=ccb77e0d-e2d7-4f49-827b-2d4ec3d655c0' \
--data-urlencode 'grant_type=refresh_token'
```

![Fluxo_5](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_5.png)


##
* O Servidor de autorização valida o refresh token e retorna um novo Access Token e um Refresh Token(pode retornar o mesmo refresh token ou um novo refresh token também de acordo com a implementação do servidor de autorização) com um novo tempo válido determinado:


```
{
    "access_token": "1885d063-80da-48c4-9883-984b678bb261",
    "token_type": "bearer",
    "refresh_token": "314df47b-c3cf-4c91-9968-354d7a7ddb8c",
    "expires_in": 14399,
    "scope": "write read"
}
```

![Fluxo_6](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_6.png)


##
* Após receber um novo token, o Client pode utilizá-lo para acessar as APIs desejadas do Resource Server:
  
![Fluxo_7](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_7.png)


### Observação:

O Resource Owner Password Credentials (fluxo de senha do proprietário do recurso) está depreciado pelo OAuth2 é não deve ser usada.




