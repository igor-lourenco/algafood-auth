# Fluxo Authorization Code + PKCE


O Authorization Code(fluxo código de autorização) envolve a troca de um código de autorização por um token. Esse fluxo só pode ser usado para aplicativos confidenciais (como aplicativos Web comuns) porque os métodos de autenticação do aplicativo estão incluídos na troca e devem ser mantidos seguros.

O PKCE é uma especificação sobre uma contramedida contra o ataque de interceptação de código de autorização. Nessa especificação foram adicionados os parâmetros:

- `code_challenge_method` = Qual lógica será usada para converter o code_verifier em code_challenge, os valores esperados são: plain ou s256

    - O plain: não altera a entrada, então o valor de code_verifier e o valor resultante de code_challenge são iguais.
    - O s256: Faz o cálculo usando o o hash criptográfico SHA-256 do valor do code_verifier, e o hash gerado é codificado Base64 URL.

- `code_verifier` = O cliente gera uma string aleatória de tamanho suficiente (pelo menos 43 caracteres).

- `code_challenge` = O cliente gera um code_challenge a partir do code_verifier usando o plain ou algoritmo SHA-256, de acordo com valor que foi passado no parâmetro code_challenge_method.

  ![Imagem_9](https://github.com/igor-lourenco/algafood-auth/blob/main/images/imagem_9.png)

Obs: Link útil para gerar de exemplo o code_verifier e code_challenge usando o hash SHA-256: https://tonyxu-io.github.io/pkce-generator/


## Fluxo de Autenticação
* O Resource Owner acessa aplicação Client:

![Fluxo_0](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_0.png)


##
* O Client gera o code_verifier e code_challenge e aramazena em algum lugar dependendo da sua implementação:

![Fluxo_1](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_1.png)

Obs: A cada nova requisição o Client tem que gerar um code_challenge aleatória.


##
* Depois que o code_verifier e code_challenge foram gerados, o Client faz uma solicitação para o Authorization Server com os parâmetros: response_type, client_id, redirect_uri, code_challenge, code_challenge_method:

```
http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalitics&redirect_uri=http://aplicacao_cliente&code_challenge=zM4FAbG0x5c9tVQHopDPRXQnFT4DBxRdRLv5eNc4hg0&code_challenge_method=s256
```
  
![Fluxo_2](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_2.png)


##
* O Authorization Server solicita a autenticação do Resource Owner, e lista as opções de permissões de autorização de acesso que Resource Owner dará ao Client:

![Fluxo_3](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_3.png)


##
* Depois que o Resource Owner autoriza, o Authorization Server armazena o code_challenge e o code_challenge_method enviado pelo Client e retorna um código de autorização e redireciona para a uri que foi especificada no parametro redirect_uri que está cadastrada no Authorization Server:

```
http://aplicacao-cliente/?code=KUnNd0
```

![Fluxo_4](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_4.png)


##
* Depois que o Authorization Server retornar o código de autorização, o Client faz a requisição para o Authorization Server passando suas credenciais codificadas em Base64, o código de autorização, redirect_uri, grant_type e code_verifier:

```
curl --location -X POST 'http://localhost:8081/oauth/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic Zm9vZGFuYWxpdGljczpmb29kMTIz' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=IY4EHF' \
--data-urlencode 'redirect_uri=http://aplicacao_cliente' \
--data-urlencode 'code_verifier=LSeXn2-72dH9NELNF_WI-fxo14gXa9clfQ-_W-t1XxQ'
```

![Fluxo_5](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_5.png)


O Authorization Server valida:
 - o código de autorização
 - as credenciais do Client
 - e aplica a lógica do plain ou algoritmo SHA-256 ao code_verifier que foi passado o code_challenge_method no começo desse fluxo, e verifica se o resultado  do algortimo aplicado ao code_verifier é o resultado com o code_challenge enviado anteriormente

![Fluxo_6](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_6.png)


 e se esiver tudo validado o Authorization Server gera um access token e retorna para o Client

```
{
    "access_token": "08158a9b-303b-4ce4-92f2-498c44db3ed0",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "read write"
}
```

![Fluxo_7](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_7.png)

Obs: O codigo de autorização é válido apenas uma vez, tanto se o Authorization Server retornar o sucesso ou erro na geração do access token, o código de autorização é automaticamente invalidado pelo Authorization Server.

##
* Após receber o token, o Client pode utilizá-lo para acessar as APIs desejadas do Resource Server:

![Fluxo_8](https://github.com/igor-lourenco/algafood-auth/blob/main/images/fluxo_8.png)










