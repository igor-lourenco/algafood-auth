# Fluxo Authorization Code

O Authorization Code(fluxo código de autorização) envolve a troca de um código de autorização por um token. Esse fluxo só pode ser usado para aplicativos confidenciais (como aplicativos Web comuns) porque os métodos de autenticação do aplicativo estão incluídos na troca e devem ser mantidos seguros.

## Fluxo de Autenticação

* O Resource Owner acessa aplicação Client com os parâmetros: `response_type`, `client_id, state`, `redirect_uri`

```
http://localhost:8081/oauth/authorize?
response_type=code&client_id=foodanalitics&state=123&redirect_uri=http://aplicacao-cliente
```
##
* E o Client redireciona para o Authorization Server solicitado autorização, para o Resource Owner se autenticar:

![Fluxo_0](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_0.png)

##
* Assim que o Resource Owner é autenticado, o Authorization Server lista as opções de permissões de autorização de acesso que Resource Owner dará ao Client:


![Fluxo_1](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_1.png)

##
* Depois que o Resource Owner autoriza, o Authorization Server retorna um código de autorização e redireciona para a uri que foi especificada no parametro redirect_uri e está cadastrada no Authorization Server:
  
```
http://aplicacao-cliente/?code=4cP5tu&state=123
```
![Fluxo_2](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_2.png)

##
* Depois que o Authorization Server retornar o código de autorização, o Client faz a requisição para o Authorization Server passando suas credenciais codificadas em Base64, o código de autorização, redirect_uri e grant_type:

``` 
curl --location -X POST 'http://localhost:8081/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic Zm9vZGFuYWxpdGljczpmb29kMTIz' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=4cP5tu' \
--data-urlencode 'redirect_uri=http://aplicacao-cliente'
```
![Fluxo_3](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_3.png)

##
*  O Authorization Server verifica o código de autorização, o client_id do aplicativo e as credenciais do aplicativo, e se esiver tudo validado responde com um access token (e opcionalmente um refresh token).

```
{
    "access_token": "08158a9b-303b-4ce4-92f2-498c44db3ed0",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "read write"
}
```
![Fluxo_4](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_4.png)

Obs: O codigo de autorização é válido apenas uma vez, tanto se o Authorization Server retornar o sucesso ou erro na geração do access token, o código de autorização é automaticamente invalidado pelo Authorization Server.



## 
* Após receber o token, o Client pode utilizá-lo para acessar as APIs desejadas do Resource Server:
  
![Fluxo_5](https://github.com/igor-lourenco/algafood-auth/blob/feature/fluxo_Authorization_Code/images/fluxo_5.png)







