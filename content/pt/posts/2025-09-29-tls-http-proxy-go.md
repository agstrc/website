---
title: "Construindo um Proxy HTTP com Inspeção MITM em Go: Entendendo TLS, Certificados e
 Segurança de Rede"
date: 2025-09-29
slug: "tls-http-proxy-go"
# description: "A deep dive into TLS, HTTP proxies, and Go by building an HTTP proxy
#   that performs MITM inspection of HTTP and HTTPS requests."
description: "Um aprofundamento em TLS, proxies HTTP, e Go, ao construir um proxy HTTP
    que executa inspeções MITM de requisições HTTP e HTTPS"
translationKey: "tls-http-proxy-go"
---

Eu construí um proxy HTTP simples que intercepta e inspeciona tanto tráfego HTTP quanto
HTTPS em Go. Este projeto demonstrou como as interfaces `net/http`, `crypto/tls` e
`net.Conn` do Go trabalham juntas. Vale destacar que este post foca exclusivamente em
proxies (forward proxies), não em proxies reversos.

O projeto final é capaz de:

- Fazer proxy de conexões HTTP
- Fazer proxy de conexões HTTPS
- Registrar pares de requisição/resposta de todas as conexões HTTP(S) (*assumindo que você controla as autoridades certificadoras do cliente*)
- Encaminhar fluxos de dados TCP de forma transparente

Este post assume familiaridade básica com HTTP, TLS e Go, mas não requer conhecimento
profundo desses tópicos.

## HTTP vs HTTPS

O [Protocolo de Transferência de Hipertexto (HTTP)](https://www.cloudflare.com/pt-br/learning/ddos/glossary/hypertext-transfer-protocol-http/)
implementa a mesma semântica de requisição/resposta independentemente do transporte
subjacente. O HTTP simples opera diretamente sobre uma conexão TCP, enviando todos os
dados como texto puro. HTTPS usa semântica HTTP idêntica, mas opera sobre um canal TLS
criptografado em vez de TCP puro.

Fazer proxy de requisições HTTP simples é direto: basta interpretar, encaminhar e
retransmitir a resposta de volta ao cliente. HTTPS, no entanto, apresenta um desafio
fundamental: toda a comunicação é criptografada em trânsito, impedindo que qualquer
intermediário inspecione o tráfego. Essa barreira de criptografia adiciona complexidade
significativa à implementação do proxy, que vamos explorar mais adiante. Para entender
por que HTTPS cria esses desafios, primeiro precisamos examinar como funciona a
criptografia TLS.

## TLS

[TLS](https://www.cloudflare.com/pt-br/learning/ssl/transport-layer-security-tls/) é o
protocolo mais amplamente usado para fornecer criptografia em trânsito. Ele permite que
duas partes distintas estabeleçam um canal de comunicação seguro sem compartilhar
segredos previamente, começando em um canal não criptografado.

TLS combina dois tipos de criptografia: assimétrica e simétrica. A criptografia
assimétrica usa um par de chaves (pública e privada) onde dados criptografados com uma
chave só podem ser descriptografados com a outra. Isso resolve o problema de troca de
chaves, mas é computacionalmente caro. A criptografia simétrica usa uma única chave
compartilhada para criptografia e descriptografia — é muito mais rápida, mas requer que
ambas as partes de alguma forma concordem com a mesma chave secreta.

Outro aspecto crucial do TLS é que ele fornece tanto criptografia quanto verificação de
identidade. TLS não apenas cria um canal seguro onde observadores externos não podem ler
os dados transmitidos, mas também verifica que você está se comunicando com o destino
real e não com um impostor.

Essa verificação depende de certificados digitais que os servidores apresentam ao
estabelecer uma conexão. Esses certificados contêm a chave pública do servidor e
informações identificadoras. No entanto, qualquer pessoa poderia criar um certificado
alegando ser qualquer site, então como sabemos se um certificado é legítimo?

A resposta está nas Autoridades Certificadoras (CAs) e nas
[assinaturas digitais](https://pt.wikipedia.org/wiki/Assinatura_digital). CAs confiáveis
assinam digitalmente certificados legítimos, criando uma prova criptográfica de que o
certificado é autêntico. Seu navegador vem pré-instalado com uma lista de CAs confiáveis
e, ao conectar-se a um site, verifica se o certificado do servidor foi devidamente
assinado por uma dessas autoridades confiáveis.

Esse sistema de verificação de CA é crucial para entender por que nosso proxy MITM requer
controle sobre a lista de CAs confiáveis do cliente. Sem isso, o proxy não pode
apresentar certificados que o cliente aceitará como legítimos.

Toda essa verificação e troca de chaves acontece durante o que chamamos de handshake TLS.
Este é o processo de negociação que ocorre antes de enviar as requisições e respostas HTTP.

### Processo de Handshake TLS

Esta é uma visão simplificada do que acontece durante um handshake TLS:

1. **Client Hello**: Seu navegador envia uma requisição ao servidor, incluindo métodos de criptografia suportados
2. **Server Hello + Certificado**: O servidor responde com seu método de criptografia escolhido e apresenta seu certificado digital (contendo a chave pública)
3. **Verificação do Certificado**: Seu navegador verifica se o certificado foi assinado por uma CA confiável
4. **Troca de Chaves**: Usando a chave pública do servidor, seu navegador criptografa um valor aleatório e o envia ao servidor
5. **Geração de Chave de Sessão**: Ambas as partes usam esse valor aleatório para gerar chaves de criptografia simétrica idênticas
6. **Comunicação Segura**: Todos os dados subsequentes são criptografados usando a criptografia simétrica rápida com a chave de sessão compartilhada

## A base do Proxy HTTP

Um proxy HTTP é um servidor que encaminha requisições usando o protocolo HTTP como seu
canal de controle. Embora comumente usado para tráfego HTTP, ele também pode tunelar
conexões TCP arbitrárias através de requisições HTTP CONNECT. A designação "HTTP"
refere-se a como os clientes se comunicam com o proxy, não necessariamente aos dados
sendo enviados pelo proxy.

### HTTP Simples

Fazer proxy de requisições HTTP simples é bem direto. A principal diferença das conexões
diretas é que os clientes enviam a URL completa de destino na linha de requisição. Em vez
de `GET /path HTTP/1.1`, o cliente envia `GET http://example.com/path HTTP/1.1` para o
proxy, que então encaminha a requisição para o servidor de destino.

Todos os outros aspectos da requisição permanecem inalterados: cabeçalhos, corpo e
métodos HTTP são encaminhados diretamente. O proxy apenas remove
[cabeçalhos hop-by-hop](https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Headers#hop-by-hop_headers)
que se aplicam à conexão entre cliente e proxy (como `Connection` e `Proxy-Authorization`)
em vez de todo o caminho da requisição até o servidor de destino.

### HTTPS

HTTPS apresenta um desafio diferente para proxies. Como a comunicação é criptografada em
trânsito entre cliente e servidor, um proxy tradicional não pode simplesmente encaminhar
requisições HTTP individuais como normalmente faria, porque não consegue ver os dados do
protocolo HTTP dentro do fluxo TLS criptografado.

A solução é o método HTTP CONNECT. Quando um cliente quer acessar um site HTTPS através
de um proxy, ele envia uma requisição CONNECT como `CONNECT example.com:443 HTTP/1.1`.
Isso diz ao proxy para estabelecer um túnel TCP puro até o servidor de destino. O proxy
responde com qualquer status **2xx** e então age como um simples relay TCP, encaminhando
bytes em ambas as direções sem interpretação.

Neste ponto, o proxy efetivamente se torna transparente. O cliente agora tem um canal criptografado
direto para o servidor e pode enviar requisições HTTP normais (como `GET /path HTTP/1.1`)
em vez do formato de URL completa usado para proxy HTTP simples. O proxy simplesmente
encaminha todos os dados criptografados sem entender o que está dentro, enquanto cliente
e servidor realizam seu handshake TLS e trocam mensagens HTTP diretamente através deste
túnel.

Como CONNECT estabelece túneis TCP puros, não está limitado a HTTPS. Qualquer protocolo
baseado em TCP pode ser tunelado através de proxies HTTP usando este método.

## Man-in-the-Middle (MITM)

Lembre-se da seção TLS que as CAs fornecem prova criptográfica da identidade de um
servidor. Esse sistema de verificação de CA é o que normalmente previne ataques
man-in-the-middle. Os clientes confiam apenas em certificados assinados por autoridades
reconhecidas, garantindo que estão se comunicando com o servidor desejado.

Para inspecionar tráfego HTTPS via MITM, o proxy precisa se interpor entre cliente e
servidor, mantendo sessões TLS independentes em cada lado. Isso envolve terminar a
conexão TLS do cliente usando um certificado próprio do proxy (geralmente assinado por
uma CA controlada pelo operador do proxy), permitindo descriptografar e analisar o
conteúdo HTTP. Após a inspeção, o proxy estabelece uma nova conexão TLS com o servidor
de destino e encaminha as requisições. Assim, o proxy atua como "servidor" para o
cliente e como "cliente" para o servidor, mantendo dois canais TLS distintos.

Para nossa aplicação, o proxy deve gerar certificados dinamicamente para cada host que
intercepta. Desde que esses certificados gerados dinamicamente sejam assinados pela CA
raiz do proxy e essa CA seja confiável pelo cliente, o navegador os aceitará como
legítimos. Isso permite que o proxy apresente certificados válidos para qualquer domínio
enquanto mantém a confiança do cliente.

## Implementação

Finalmente, temos uma base sólida para implementar.

### Proxy HTTP Simples

Ao implementar proxy HTTP simples, a abordagem inicial pode parecer direta:

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    resp, _ := http.DefaultClient.Do(r) // tratamento de erros será omitido em nome da brevidade
    // escrever resposta de volta em w
}
```

Porém essa implementação falha com um erro:
`Get "http://example.com": http: Request.RequestURI can't be set in client requests`.
Esse erro destaca como Go trata instâncias `*http.Request` de forma diferente para
contextos de servidor e cliente.

Com isso em mente, lembre-se dos cabeçalhos hop-by-hop. Temos que fazer os ajustes que Go
considera necessários, assim como remover os cabeçalhos.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    // Criar uma nova requisição para o servidor upstream
    upstreamReq, _ := http.NewRequest(r.Method, r.RequestURI, r.Body)

    // Copiar cabeçalhos e remover cabeçalhos hop-by-hop
    upstreamReq.Header = r.Header.Clone()
    removeHopByHopHeaders(upstreamReq.Header)

    // Limpar o campo RequestURI para requisições de cliente
    upstreamReq.RequestURI = ""

    resp, _ := http.DefaultClient.Do(upstreamReq)
}
```

Veja que eu usei `r.RequestURI` como a URL. Lembre-se que clientes com proxy enviam a URL
completa de destino na linha de requisição. `RequestURI` preserva isso exatamente como
recebido, tornando-o perfeito para implementações de proxy. A documentação afirma:

> RequestURI is the unmodified request-target of the
> Request-Line (RFC 7230, Section 3.1.1) as sent by the client
> to a server. Usually the URL field should be used instead.
> It is an error to set this field in an HTTP client request.

Alternativamente, `r.URL.String()` poderia ser usado. Em requisições sem proxy, `r.URL`
contém apenas o componente da rota sem esquema ou host, ilustrando ainda mais como Go
lida com contextos de requisição de forma diferente.

Podemos implementar `removeHopByHopHeaders` como:

```go
func removeHopByHopHeaders(header http.Header) {
   var hopByHopHeaders = []string{
      "Connection",
      "Proxy-Connection",
      "Keep-Alive",
      "Proxy-Authenticate",
      "Proxy-Authorization",
      "TE",
      "Trailer",
      "Transfer-Encoding",
      "Upgrade",
   }

   for _, h := range hopByHopHeaders {
      header.Del(h)
   }
}
```

Agora, escreva a resposta de volta no `http.ResponseWriter`.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    // ... código anterior ...
    resp, _ := http.DefaultClient.Do(upstreamReq)
    defer resp.Body.Close()

    // Copiar cabeçalhos de resposta, removendo cabeçalhos hop-by-hop
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)

    // Limpar cabeçalhos existentes e copiar os filtrados
    clear(w.Header())
    maps.Copy(w.Header(), responseHeaders)

    // Escrever código de status e transmitir corpo
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

Clientes HTTP em Go gerenciam redirecionamentos e cookies automaticamente através de
campos configuráveis. Contudo, ao fazer proxy de requisições, idealmente você quer que o
cliente downstream lide com esses comportamentos em vez do proxy tomar decisões. Por essa
razão, minha implementação usa `http.Transport` diretamente em vez de `http.Client`, já
que `transport.RoundTrip(req)` ignora o seguimento de redirecionamentos e o tratamento de
cookies que `client.Do(req)` aplicaria.

Com esse handler completo, já podemos fazer proxy de requisições HTTP simples. O proxy
lida corretamente com o formato de URL completa, filtra cabeçalhos hop-by-hop e
transmite respostas de volta aos clientes preservando o comportamento original do
servidor.

### Proxy HTTPS

Agora vem a parte divertida. Faremos proxy de requisições HTTPS por meio do método
CONNECT.

#### Requisições CONNECT e http.Hijacker

Suponha que recebemos um `CONNECT example.com:443 HTTP/1.1`. Podemos, mais uma vez, usar
`r.RequestURI`.

```go
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodConnect {
        host, port, _ := net.SplitHostPort(r.RequestURI)

        // Sequestrar a conexão para tunelamento
        hijacker, ok := w.(http.Hijacker)
        if !ok {
            http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
            return
        }
        conn, _, _ := hijacker.Hijack()

        // Enviar resposta de conexão estabelecida
        conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

        // Lidar com diferentes tipos de conexão baseados na porta
        if port == "443" {
            handleHTTPSConnection(conn, host)
        } else {
            handleTCPConnection(conn, host, port)
        }
        return
    }

    // Lidar com requisições HTTP regulares (código anterior)
    // ...
}
```

A interface [`http.Hijacker`](https://pkg.go.dev/net/http@go1.25.1#Hijacker) nos permite
tomar controle da conexão TCP base. Isso nos permite acesso direto ao `net.Conn`.
Ressalto que conexões HTTP/2 intencionalmente não suportam hijacking, então handlers
devem sempre testar essa capacidade em runtime.

Após enviar a resposta `200 Connection Established`, o cliente espera estabelecer uma
conexão TLS através deste túnel. O proxy agora pode realizar TLS termination para
inspecionar o tráfego.

#### TLS termination

Primeiro precisamos de um certificado para o host de destino que o cliente está tentando alcançar. Isso requer geração dinâmica de certificados, já que o proxy não pode prever quais hosts os clientes solicitarão durante a execução.

Primeiro, precisamos de uma CA:

```go
func generateCA() (*x509.Certificate, *rsa.PrivateKey) {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    ca := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "Proxy CA"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        IsCA:         true,
        KeyUsage:     x509.KeyUsageCertSign,
    }
    caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
    parsedCA, _ := x509.ParseCertificate(caBytes)
    return parsedCA, priv
}
```

Tambem é possivel carregar uma CA existente do disco. Isso é preferível para uso real, já
que os clientes precisam confiar na CA, e uma CA gerada dinamicamente não pode ser pré
instalada nas configurações de confiança do cliente:

```go
certPEM, _ := os.ReadFile("ca.crt")
keyPEM, _ := os.ReadFile("ca.key")
cert, _ := tls.X509KeyPair(certPEM, keyPEM)
caCert, _ := x509.ParseCertificate(cert.Certificate[0])
```

Com a CA estabelecida, podemos gerar certificados para qualquer hostname sob demanda:

```go
func generateCertificate(hostname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)

    // Gerar número serial aleatório - navegadores podem rejeitar números seriais reutilizados
    serialNumber, _ := rand.Int(rand.Reader, big.NewInt(1<<62))

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject:      pkix.Name{CommonName: hostname},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames:     []string{hostname},
    }
    certBytes, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
    return tls.Certificate{
        Certificate: [][]byte{certBytes, caCert.Raw},
        PrivateKey:  priv,
    }
}
```

Agora podemos fazer TLS termination envolvendo nossa conexão. É aqui que a interceptação
MITM acontece: em vez de estabelecer um túnel transparente, o proxy apresenta seu próprio
certificado ao cliente, criando uma conexão TLS que ele pode descriptografar e
inspecionar:

```go
cert := generateCertificate(host, caCert, caKey)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    NextProtos:   []string{"h2", "http/1.1"},
}

tlsConn := tls.Server(conn, tlsConfig)
tlsConn.Handshake()
```

O campo `NextProtos` especifica protocolos de aplicação suportados para
[ALPN (Application-Layer Protocol Negotiation)](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).
Isso permite que os clientes negociem se usarão HTTP/2 ou HTTP/1.1 sobre a conexão TLS, o
que é importante para compatibilidade web moderna.

Note que `tlsConn.Handshake()` poderia ser omitido, já que a maioria das aplicações
acionará o handshake automaticamente na primeira operação de leitura ou escrita. No
entanto, chamá-lo explicitamente nos permite falhar rapidamente se o handshake falhar, em
vez de encontrar o erro mais tarde durante o processamento da requisição.

### Intepretando pacotes HTTP

Agora vamos analisar as requisições HTTP para fazer proxy delas de forma similar.

Para HTTP, Go fornece diferentes abordagens dependendo da versão do protocolo. Para
HTTP/2, poderíamos usar [`http2.Server.ServeConn()`](https://pkg.go.dev/golang.org/x/net@v0.44.0/http2#Server.ServeConn)
para lidar com a conexão diretamente. Para HTTP/1.x, poderíamos usar
[`http.ReadRequest()`](https://pkg.go.dev/net/http@go1.25.1#ReadRequest) para analisar
requisições individuais da conexão.

No entanto, essa abordagem dividiria nossa lógica de tratamento. Iriamos precisar de
caminhos de código separados para HTTP/1.x e HTTP/2, tornando nosso proxy mais complexo.
Ainda mais, para HTTP/1.x, usar apenas `http.ReadRequest()` não fornece gerenciamento de
sconexão. Recursos como HTTP keep-alive, pool de conexões e gerenciamento adequado do
ciclo de vida da conexão simplesmente falhariam ou exigiriam implementação adicional
significativa.

Em vez disso, podemos aproveitar o `http.Server` do Go que já lida com HTTP/1.x e HTTP/2
de forma transparente, gerencia conexões adequadamente e fornece uma interface unificada
independentemente da versão do protocolo subjacente.

O `http.Server` normalmente escuta conexões TCP e as gerencia diretamente. Mas como
podemos alimentar nossas conexões existentes ao servidor? É aqui que [`net.Listener`](https://pkg.go.dev/net@go1.25.1#Listener)
entra em ação. O servidor HTTP do Go aceita conexões através de uma interface listener.
Podemos implementar um listener personalizado que fornece nossas conexões existentes ao
servidor.

Podemos começar com o seguinte:

```go
type SingleListener struct {
    conn     net.Conn
    accepted bool
}

func (l *SingleListener) Accept() (net.Conn, error) {
    if l.accepted {
        return nil, errors.New("listener closed")
    }
    l.accepted = true
    return l.conn, nil
}

func (l *SingleListener) Close() error {
    return nil // noop
}

func (l *SingleListener) Addr() net.Addr {
    return l.conn.LocalAddr()
}
```

No entanto, essa abordagem tem uma falha crítica: `http.Server` falhará assim que o
listener retornar seu primeiro erro de `Accept()`. Isso significa que após lidar com uma
única conexão, o loop de aceitação do servidor termina. Isso pode fazer com que as conexões
sejam fechadas, o que vai contra nosso objetivo de manter controle total sobre o ciclo de
vida da conexão e fornecer um serviço de proxy estável.

```go
type SingleListener struct {
    conn      net.Conn
    accepted  atomic.Bool
    closeChan chan struct{}
    closeOnce sync.Once
}

func NewSingleListener(conn net.Conn) *SingleListener {
    return &SingleListener{
        conn:      conn,
        closeChan: make(chan struct{}),
    }
}

func (l *SingleListener) Accept() (net.Conn, error) {
    if l.accepted.CompareAndSwap(false, true) {
        return l.conn, nil
    }

    <-l.closeChan
    return nil, errors.New("listener closed")
}

func (l *SingleListener) Close() error {
    l.closeOnce.Do(func() {
        close(l.closeChan)
    })
    return nil
}

func (l *SingleListener) Addr() net.Addr {
    if l.conn != nil {
        return l.conn.LocalAddr()
    }
    return nil
}
```

Ótimo! Esta implementação fornece um listener que retorna uma única conexão e então
bloqueia até ser explicitamente fechado. As operações atômicas e o bloqueio baseado em
channels garantem que seja seguro para uso concorrente. O `sync.Once` garante que o
listener fecha apenas uma vez, embora a implementação interna de `http.Server` já forneça
proteção similar.

Agora podemos usar este listener para lidar com nossa conexão TLS com um servidor HTTP:

```go
func handleHTTPSConnection(conn net.Conn, host string) {
    // Gerar certificado para o host de destino
    cert := generateCertificate(host, caCert, caKey)

    // Realizar terminação TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        NextProtos:   []string{"h2", "http/1.1"},
    }

    tlsConn := tls.Server(conn, tlsConfig)
    tlsConn.Handshake()

    // Criar listener para esta única conexão
    listener := NewSingleListener(tlsConn)
    defer listener.Close()

    // Criar servidor HTTP com handler de injeção de host
    server := &http.Server{
        Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
            // Injetar contexto de host da requisição CONNECT
            upstreamReq := r.Clone(r.Context())
            upstreamReq.URL.Scheme = "https"
            upstreamReq.URL.Host = host
            upstreamReq.RequestURI = ""
            removeHopByHopHeaders(upstreamReq.Header)

            // Encaminhar usando a lógica de proxy existente
            forwardHTTPSRequest(rw, upstreamReq)
        }),
    }

    server.Serve(listener)
}
```

O destaque nesta implementação é como preservamos o hostname de destino da requisição
CONNECT original e o injetamos em cada requisição HTTP. Após o TLS termination, os
clientes enviam requisições apenas com o caminho como `GET /path HTTP/1.1` sem o hostname
completo, mas nosso handler reconstrói a URL completa usando o host capturado durante a
fase CONNECT. Isso garante proxying confiável independentemente do que aparece no
cabeçalho Host.

A função `forwardHTTPSRequest` implementaria a mesma lógica de encaminhamento que o
handler de proxy HTTP simples mostrado anteriormente, mas operando na requisição
reconstruída com a URL completa.

Agora, temos apenas um problema final. O código atual vai iniciar um servidor que irá
rodar para sempre. Sua goroutine aceitando as conexões simplesmente ficará presa. Como
podemos saber quando fechar o servidor? Podemos usar a callback ConnState do servidor.

> ConnState specifies an optional callback function that is
> called when a client connection changes state. See the
> ConnState type and associated constants for details.

Lembre-se que usar `http.ReadRequest()` diretamente exigiria que lidássemos manualmente
com o ciclo de vida da conexão e gerenciamento de keep-alive. O `http.Server` lida com
isso automaticamente, rastreando conexões através de estados como `StateNew`,
`StateActive`, `StateIdle` (para keep-alive) e `StateClosed`. Para nosso proxy de
conexão única, podemos monitorar esses estados para desligar quando a conexão termina:

```go
func handleHTTPSConnection(conn net.Conn, host string) {
    // ... código de terminação TLS ...

    server := &http.Server{
        Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
            // ... lógica de encaminhamento de requisição ...
        }),
        ConnState: func(c net.Conn, cs http.ConnState) {
            if cs == http.StateClosed || cs == http.StateHijacked {
                server.Close()
            }
        },
    }

    listener := NewSingleListener(tlsConn)
    server.Serve(listener)
}
```

Implementamos com sucesso o proxy HTTP e HTTPS. No entanto, nosso propósito ao
implementar TLS termination e inspeção MITM é inspecionar o tráfego descriptografado.
Nossa implementação atual encaminha requisições mas não captura ou analisa os dados que
fluem através do proxy. Vamos dar um jeito nisso.

### Logs de Requisição/Resposta

Para capturar e inspecionar o tráfego fluindo através do nosso proxy, precisamos
registrar tanto as requisições quanto as respostas. Vamos extrair a lógica de
encaminhamento em uma função separada e adicionar registro após o par requisição/resposta
ser concluído:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    // ... código anterior de encaminhamento de requisição ...

    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // ... copiar cabeçalhos e status da resposta ...
    // ... copiar corpo da resposta para o cliente ...

    // Registrar o par completo de requisição/resposta
    reqBody, _ := io.ReadAll(req.Body)
    respBody, _ := io.ReadAll(resp.Body)

    fmt.Printf("=== TRÁFEGO INTERCEPTADO ===\n")
    fmt.Printf("REQUISIÇÃO: %s %s\n", req.Method, req.URL)
    fmt.Printf("Corpo da Requisição: %s\n", reqBody)
    fmt.Printf("RESPOSTA: %d %s\n", resp.StatusCode, resp.Status)
    fmt.Printf("Corpo da Resposta: %s\n", respBody)
    fmt.Printf("============================\n")
}
```

Essa abordagem tem um problema fundamental. No momento em que tentamos ler os corpos de
requisição e resposta para registro, eles já foram consumidos durante o processo de
encaminhamento. Vamos ver como é realmente o encaminhamento adequado de requisição:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    // ... código anterior de preparação de cabeçalhos ...

    // Corpo da requisição é consumido durante RoundTrip
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copiar cabeçalhos de resposta
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)
    clear(rw.Header())
    maps.Copy(rw.Header(), responseHeaders)

    // Escrever status e transmitir corpo para o cliente
    rw.WriteHeader(resp.StatusCode)
    io.Copy(rw, resp.Body) // Corpo da resposta é consumido aqui
}
```

A operação `io.Copy(rw, resp.Body)` consome todo o corpo da resposta enquanto o transmite
para o cliente. Uma vez que isso acontece, `resp.Body` está esgotado e não pode ser lido
novamente. Da mesma forma, se a requisição tiver um corpo, será consumido durante
`RoundTrip()`.

Para capturar o conteúdo do corpo para registro enquanto ainda o transmitimos
adequadamente, precisamos de uma maneira de "bifurcar" o fluxo de dados. Iremos ler ele
uma vez, mas vamos o manter disponível em memória.

A biblioteca padrão do Go fornece `io.TeeReader` para esse propósito, mas tem uma
pegadinha: quando modificamos diretamente o corpo da requisição (ao invés de criar uma
nova requisição), devemos preservar a interface `io.ReadCloser`. O transporte HTTP
espera poder fechar o corpo após o uso, como documentado:

> RoundTrip must always close the body, including on errors, but depending on the
> implementation may do so in a separate goroutine even after RoundTrip returns.
> This means that callers wanting to reuse the body for subsequent requests must
> arrange to wait for the Close call before doing so.

Como estamos substituindo `req.Body` com nosso tee reader, ele deve implementar
`io.ReadCloser` para satisfazer as expectativas do transporte. Esse requisito vem do
nosso design: pegamos um `*http.Request` existente em nossa função de encaminhamento e
o modificamos diretamente, assumindo que ajustes adequados de cabeçalho já foram feitos
pelo handler do servidor HTTP. Embora pudéssemos lidar com o fechamento explicitamente
e usar `io.NopCloser`, nossa abordagem de modificar a requisição diretamente requer
preservar o contrato de interface original. Isso requer implementar nosso próprio
`TeeReadCloser`:

```go
type TeeReadCloser struct {
   reader io.ReadCloser
   writer io.Writer
}

func NewTeeReadCloser(r io.ReadCloser, w io.Writer) *TeeReadCloser {
   return &TeeReadCloser{
      reader: r,
      writer: w,
   }
}

func (t *TeeReadCloser) Read(p []byte) (n int, err error) {
   n, err = t.reader.Read(p)
   if n > 0 {
      if wn, werr := t.writer.Write(p[:n]); werr != nil {
         return wn, werr
      }
   }
   return n, err
}

func (t *TeeReadCloser) Close() error {
   return t.reader.Close()
}
```

Agora podemos usar este `TeeReadCloser` para capturar tanto os corpos de requisição quanto
de resposta enquanto os encaminhamos adequadamente. Para os logs, vamos usar as funções
[`httputil.DumpRequest`](https://pkg.go.dev/net/http/httputil@go1.25.1#DumpRequest) e
[`httputil.DumpResponse`](https://pkg.go.dev/net/http/httputil@go1.25.1#DumpResponse) do
Go, que formatam mensagens HTTP em sua representação de rede. Exatamente como aparecem na
rede. Isso fornece visibilidade completa dos cabeçalhos, linhas de status e conteúdo do
corpo em um formato padronizado.

Aqui está a implementação completa:

```go
func forwardHTTPSRequest(rw http.ResponseWriter, req *http.Request) {
    var requestBody, responseBody bytes.Buffer

    // Bifurcar o corpo da requisição se existir
    if req.Body != nil {
        req.Body = NewTeeReadCloser(req.Body, &requestBody)
    }

    // Encaminhar requisição para o upstream
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(rw, "Bad Gateway", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copiar cabeçalhos de resposta
    responseHeaders := resp.Header.Clone()
    removeHopByHopHeaders(responseHeaders)
    clear(rw.Header())
    maps.Copy(rw.Header(), responseHeaders)
    rw.WriteHeader(resp.StatusCode)

    // Bifurcar o corpo da resposta
    teeReader := NewTeeReadCloser(resp.Body, &responseBody)
    io.Copy(rw, teeReader)

    // Registrar o par completo requisição/resposta usando httputil
    reqCopy := req.Clone(req.Context())
    reqCopy.Body = io.NopCloser(bytes.NewReader(requestBody.Bytes()))

    respCopy := *resp
    respCopy.Body = io.NopCloser(bytes.NewReader(responseBody.Bytes()))

    fmt.Printf("=== TRÁFEGO INTERCEPTADO ===\n")

    // DumpRequest formata a requisição no formato de rede HTTP
    reqDump, _ := httputil.DumpRequest(reqCopy, true)
    fmt.Printf("REQUISIÇÃO:\n%s\n", reqDump)

    // DumpResponse formata a resposta no formato de rede HTTP
    respDump, _ := httputil.DumpResponse(&respCopy, true)
    fmt.Printf("RESPOSTA:\n%s\n", respDump)

    fmt.Printf("============================\n")
}
```

Agora temos logging e proxy HTTPS completos. Nossa implementação intercepta tráfego
criptografado por TLS, descriptografa-o para inspeção e o encaminha para o servidor
upstream enquanto captura a conversa HTTP completa. A lógica de encaminhamento e
logs para requisições HTTP simples segue praticamente o mesmo padrão, apenas sem a
etapa de TLS termination.

### Tunelamento TCP Puro

Para requisições CONNECT em portas diferentes de 80 ou 443, nosso proxy deve estabelecer
um túnel TCP transparente sem qualquer tratamento específico de protocolo. Isso cobre
protocolos TCP arbitrários e até conexões HTTPS em portas não padrão, onde o proxy age
como um proxy tradicional não invasivo:

```go
func handleTCPConnection(conn net.Conn, host, port string) {
    // Conectar ao servidor upstream
    target := net.JoinHostPort(host, port)
    upstream, err := net.Dial("tcp", target)
    if err != nil {
        conn.Close()
        return
    }
    defer upstream.Close()

    // Criar relay de dados bidirecional
    done := make(chan struct{}, 2)

    go func() {
        defer func() { done <- struct{}{} }()
        io.Copy(upstream, conn)
        upstream.Close()
    }()

    go func() {
        defer func() { done <- struct{}{} }()
        io.Copy(conn, upstream)
        conn.Close()
    }()

    <-done
}
```

Esta implementação cria duas goroutines que copiam dados bidirecionalmente entre o
cliente e o servidor upstream. Diferentemente do nosso handler HTTPS, não há inspeção
ou modificação. Se um cliente usa HTTPS em uma porta não padrão, o tráfego permanece
criptografado.

## Conclusão

Construímos um proxy HTTP completo com capacidades MITM que pode interceptar,
descriptografar e registrar tanto tráfego HTTP quanto HTTPS. Nossa implementação cobre
todos os três modos de proxy: encaminhamento HTTP, HTTPS com terminação TLS e tunelamento
TCP transparente.

### Exemplo de Uso

Para uma implementação completa funcional com tratamento de erros, registro e opções de
configuração, veja [github.com/agstrc/http-logging-proxy](https://github.com/agstrc/http-logging-proxy).

Aqui está como você pode usar o proxy completo:

```bash
# Iniciar o servidor proxy
./proxy -port 8080 -logpath traffic.log

# Fazer requisições através do proxy
curl -x localhost:8080 http://example.com
curl -k -x localhost:8080 https://example.com

# Visualizar tráfego interceptado
cat traffic.log
```

O proxy registra pares completos de requisição/resposta no formato de rede HTTP:

```plain
=== TRÁFEGO INTERCEPTADO ===
REQUISIÇÃO:
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.0.1
Accept: */*

RESPOSTA:
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1256

<!doctype html>
<html>...
============================
```
