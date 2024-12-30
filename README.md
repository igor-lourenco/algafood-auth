# Fluxo Client Credentials

O Client Credentials Flow(Fluxo de Credenciais do Cliente) é um dos métodos de autenticação definidos pelo protocolo OAuth 2.0, utilizado principalmente para permitir que aplicações acessem recursos em nome de si mesmas, em vez de um Resource Owner(Usuário Final) específico. Esse fluxo é ideal para cenários em que a aplicação precisa se autenticar diretamente com um servidor de autorização, sem a necessidade de interação do Resource Owner.

## Fluxo de Autenticação

A aplicação faz uma solicitação de token de acesso(Access Token), enviando suas credenciais de Client ID e Client Secret codificada em Base64:
```
curl --location -X POST 'http://localhost:8081/oauth/token'
--header 'Content-Type: application/x-www-form-urlencoded'
--header 'Authorization: Basic ZmF0dXJhbWVudG86ZmF0dXJhbWVudG8xMjM='
--data-urlencode 'grant_type=client_credentials'
```


![Fluxo_0](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Client_Credentials/images/fluxo_0.png)

##
Caso o Client ID e Client Secret esteja registado no servidor, retorna o Access Token para o client:
```
HTTP/1.1 200
Content-Type: application/json

{
    "access_token": "bb727e00-e6f4-46b5-8653-baabeb989a64",
    "token_type": "bearer",
    "refresh_token": "b62f9609-2e58-46fc-b4eb-3d48d26d8e36",
    "expires_in": 14399,
    "scope": "write read"
}
```

![Fluxo_1](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Client_Credentials/images/fluxo_1.png)

##
Após receber o token, a aplicação pode utilizá-lo para acessar as APIs desejadas:

![Fluxo_2](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Client_Credentials/images/fluxo_2.png)
