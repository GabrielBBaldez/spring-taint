# Spring Taint Analyzer — Visão Técnica e Escopo

> Ferramenta de análise estática interprocedural de taint para aplicações Spring Boot.  
> Detecta vulnerabilidades de fluxo de dados que ferramentas convencionais como SonarQube não alcançam.

---

## O Problema

Considere este código Spring Boot aparentemente inofensivo:

```java
// Controller
@GetMapping("/users")
public List<User> search(@RequestParam String name) {
    return userService.search(name);
}

// Service
public List<User> search(String name) {
    String filtered = nameFilter(name); // parece sanitizar, mas não sanitiza
    return userRepo.findByName(filtered);
}

// Repository
public List<User> findByName(String name) {
    return jdbc.query(
        "SELECT * FROM users WHERE name = '" + name + "'", // 🚨 SQL Injection
        mapper
    );
}
```

O dado vem de `@RequestParam`, atravessa service e repository, e chega numa query SQL sem sanitização. Um ataque trivial como `name = ' OR '1'='1` expõe toda a tabela.

**SonarQube não detecta esse caminho.** Ele só detecta o caso onde o sink está na mesma função que a source. A vulnerabilidade real vive nos fluxos que cruzam múltiplas camadas — e é exatamente aí que este projeto atua.

---

## O que é Taint Analysis

Taint analysis rastreia o fluxo de dados não confiáveis pelo sistema através de três conceitos:

```
[SOURCE] ──► fluxo de dados ──► [SANITIZER?] ──► [SINK]
                                      │
                              se ausente → alerta
```

- **Source** — onde dado externo entra no sistema: `@RequestParam`, `@RequestBody`, `@KafkaListener`
- **Sanitizer** — o que limpa o dado: `HtmlUtils.htmlEscape()`, `PreparedStatement`, `@Valid`
- **Sink** — onde dado perigoso é consumido: `JdbcTemplate.execute()`, `Runtime.exec()`, `response.write()`

Se um dado vai de uma source até um sink **sem passar por um sanitizer** → vulnerabilidade potencial.

A análise é **interprocedural**: rastreia o dado atravessando múltiplos métodos, classes e camadas de abstração — não apenas dentro de uma única função.

---

## Posicionamento: Complementar ao SonarQube

Este projeto **não substitui** o SonarQube. São ferramentas com propósitos distintos:

| Ferramenta | Propósito | Taint interprocedural |
|---|---|---|
| SonarQube | Qualidade geral + bugs + vulnerabilidades simples | ❌ |
| Semgrep OSS | Padrões de código estáticos | ❌ |
| **Semgrep Pro** | Taint interprocedural | ✅ — mas **pago** |
| Checkmarx / Veracode | SAST enterprise completo | ✅ — mas **muito caro** |
| OpenTaint | Taint para Spring (open source) | ✅ — mas incompleto |
| **Spring Taint Analyzer** | Taint interprocedural para Spring Boot | ✅ — **gratuito** |

O uso esperado em pipeline CI é:

```yaml
- sonarqube scan          # qualidade geral, code smells, cobertura
- spring-taint scan       # vulnerabilidades de fluxo de dados profundas
```

**A proposta de valor em uma frase:** você já usa SonarQube — este projeto detecta o que ele não consegue ver.

---

## Por que as Ferramentas Existentes Não Resolvem

### OpenTaint (concorrente open source mais próximo)

Tem issues abertos pelos próprios maintainers reconhecendo gaps críticos:
- Sanitizers condicionais não suportados (#169)
- Method sanitizers customizados não suportados (#170)
- Bug em stored-XSS onde apenas metade do trace é mostrada (#158)
- Nenhuma modelagem de `@KafkaListener` ou mensageria como source

### Semgrep Pro / Checkmarx / Veracode

Cobrem mais, mas:
- São pagos ou caros demais para a maioria dos times
- Não são extensíveis pela comunidade
- Não modelam stacks modernas (WebFlux, Kafka, gRPC)
- Sem transparência sobre como a análise funciona internamente

---

## Arquitetura Técnica

### Engine: Tai-e

O projeto é construído sobre **[Tai-e](https://github.com/pascal-lab/Tai-e)**, um framework moderno de análise estática para Java desenvolvido pela Nanjing University (ISSTA 2023).

**Por que Tai-e e não Soot, FlowDroid ou SootUp:**

| Framework | Problema |
|---|---|
| FlowDroid | Projetado para Android — modelo de lifecycle incompatível com Spring |
| Soot clássico | API antiga, suporte a Java source apenas até v7 |
| SootUp | Reescrita do Soot, ainda incompleta (feature-incomplete por declaração oficial) |
| **Tai-e** | Moderno, ativo, IFDS nativo, configuração YAML extensível, Java 17+ |

Tai-e resolve o problema difícil: construção de grafo de chamadas, pointer analysis sensível a contexto, e propagação IFDS interprocedural. Nosso trabalho é a camada Spring em cima dele.

### Algoritmo: IFDS

A propagação de taint usa o algoritmo **IFDS** (Interprocedural Finite Distributive Subset problems), que reduz análise de dataflow a problema de alcançabilidade em grafos. Garante:
- Sensibilidade a fluxo (flow-sensitive)
- Sensibilidade a contexto (context-sensitive) via pointer analysis do Tai-e
- Precisão interprocedural real — não pattern matching

### Pipeline

```
Projeto Spring Boot
       │
       ▼
  Compilação (Maven / Gradle)
       │
       ▼
  Bytecode (.class / JAR)          ← análise opera aqui, não no fonte
       │
       ▼
  Tai-e: Call Graph + Pointer Analysis
       │
       ▼
  IFDS Taint Propagation
       │
       ▼
  Spring Source/Sink Config        ← nosso diferencial
  (@RequestParam, @KafkaListener,
   JdbcTemplate, Runtime.exec…)
       │
       ▼
  Relatório SARIF 2.1
  (terminal / GitHub / GitLab / VS Code)
```

Operar em bytecode (não em código fonte) garante:
- Resolução precisa de herança e genéricos
- Análise de dependências de terceiros sem código fonte disponível
- Independência de IDE ou build system

---

## Escopo por Fases

### Fase 1 — Spring MVC (MVP)

Objetivo: detectar as vulnerabilidades mais comuns em projetos Spring MVC reais, com zero falsos negativos nos casos cobertos.

**Sources:**
- `@RequestParam`, `@PathVariable`, `@RequestBody`
- `@RequestHeader`, `@CookieValue`
- `@ModelAttribute`
- `HttpServletRequest.getParameter()` e variantes

**Sinks:**

| Vulnerabilidade | Sinks monitorados |
|---|---|
| SQL Injection | `JdbcTemplate.query/execute`, `Statement.execute`, `EntityManager.createNativeQuery` |
| XSS | `HttpServletResponse.getWriter().write()`, `@ResponseBody` com HTML |
| Path Traversal | `new File(input)`, `Paths.get(input)`, `FileInputStream(input)` |
| Command Injection | `Runtime.exec(input)`, `ProcessBuilder(input)` |
| SSRF | `RestTemplate.getForObject(input)`, `WebClient` com URL controlada |
| SpEL Injection | `ExpressionParser.parseExpression(input)` |
| Open Redirect | `response.sendRedirect(input)` |

**Sanitizers reconhecidos:**
- `HtmlUtils.htmlEscape()`
- `PreparedStatement` e `NamedParameterJdbcTemplate` com parâmetros
- Bean Validation (`@Valid`, `@NotNull`, `@Pattern`, `@Size`)
- Sanitizers customizados declarados via YAML

**Critério de saída da Fase 1:** detectar os casos do benchmark sem falsos negativos, com precision > 80%.

---

### Fase 2 — Gaps do OpenTaint (diferencial central)

#### 2.1 Kafka como Source

`@KafkaListener` é um vetor de entrada externo ignorado por todas as ferramentas open source:

```java
@KafkaListener(topics = "user-events")
public void onMessage(String payload) {
    // payload é TAINTED — vem de fora do sistema
    String query = "SELECT * FROM users WHERE id = " + payload;
    jdbcTemplate.execute(query); // 🚨 SQL Injection via Kafka
}
```

Será modelado via `param source` do Tai-e — exatamente o mecanismo projetado para entry points sem call site explícito.

Cobertura:
- `@KafkaListener` com payload direto como `String`
- `@RabbitListener` (RabbitMQ / Spring AMQP) com payload direto — mesmo modelo do Kafka
- `ConsumerRecord<K, V>` — `key()` e `value()` como tainted
- `@Header` em listener methods

#### 2.2 Sanitizers Condicionais

Sanitizer aplicado apenas em alguns branches de execução:

```java
public String process(String input, boolean trusted) {
    if (!trusted) {
        input = HtmlUtils.htmlEscape(input); // sanitizer condicional
    }
    return render(input); // ainda TAINTED no caminho trusted=true
}
```

A análise precisa preservar o taint no branch onde o sanitizer não é aplicado. O IFDS do Tai-e suporta flow-sensitivity — a implementação precisa explorar isso corretamente.

#### 2.3 Method Sanitizers Customizados

Métodos internos que sanitizam por contrato, mas não fazem parte de bibliotecas conhecidas:

```java
public class InputSanitizer {
    public String clean(String input) {
        return input.replaceAll("[^a-zA-Z0-9]", "");
    }
}
```

Declaração via YAML:

```yaml
sanitizers:
  - { method: "<com.myapp.InputSanitizer: java.lang.String clean(java.lang.String)>", index: 0 }
```

#### 2.4 Stored Injection Cross-Request

Dado tainted salvo no banco em uma request e lido em outra sem sanitização:

```java
// Request 1: salva dado contaminado
@PostMapping("/comment")
public void save(@RequestBody String comment) {
    repo.save(new Comment(comment)); // TAINTED persiste no banco
}

// Request 2: lê e renderiza sem sanitizar
@GetMapping("/comments")
public String list() {
    return repo.findAll()
               .stream()
               .map(Comment::getText) // ainda TAINTED
               .collect(joining("\n")); // 🚨 Stored XSS
}
```

O OpenTaint reporta apenas metade do trace (issue #158 aberto). Este projeto modela a persistência como propagador de taint, reconstruindo o trace completo.

#### 2.5 WebFlux e Código Assíncrono

Taint atravessando boundaries assíncronos:

```java
// @Async
@Async
public CompletableFuture<String> process(String userInput) {
    return CompletableFuture.completedFuture(dangerousSink(userInput)); // 🚨
}

// WebFlux
@GetMapping("/search")
public Mono<String> search(@RequestParam String query) {
    return Mono.just(query)
               .map(q -> "SELECT * FROM items WHERE name = '" + q + "'")
               .flatMap(sql -> db.execute(sql)); // 🚨
}
```

`Mono` e `Flux` são tratados como wrappers transparentes de taint — o dado dentro deles continua tainted.

---

### Fase 3 — multi-framework

| Framework | Sources | Sinks | Status |
|---|---|---|---|
| Quarkus / Jakarta REST | `@QueryParam`, `@PathParam` (JAX-RS) | Panache ORM, `EntityManager` | ✅ no repo principal |
| Micronaut | `@QueryValue`, `@Body` | JDBC, `HttpClient` | ✅ no repo principal |
| RabbitMQ | `@RabbitListener` | Qualquer sink Java existente | ✅ no repo principal |
| gRPC | Campos de mensagem Protobuf | Qualquer sink Java existente | ⏳ roadmap |

> Nota: Quarkus/Micronaut/RabbitMQ acabaram entrando no **repositório principal** (não num repo
> separado, como esboçado abaixo na seção "Repositórios"); só gRPC continua pendente.

---

### Entregue além do escopo original (análises não-taint e adoção)

O projeto cresceu além da análise de taint pura. Já no CLI:

- **Scanners de padrão (não-taint, via ASM — leem qualquer JDK):** `secrets` (credenciais hardcoded), `misconfig` (CSRF disable, CORS permissivo, cookies inseguros, dados sensíveis em log) e `config` (auditoria de `application.yml`/`.properties`: segredos, SSL, exposição de actuator, console H2).
- **Autofix:** gera o patch parametrizado para SQL injection (concat → `?` + binds) e envolve o valor em `HtmlUtils.htmlEscape` para XSS, preservando a formatação (JavaParser). `--suggest-fixes` por padrão; `--fix` aplica só os de alta confiança.
- **Near-miss sanitizers:** detecta sanitização *tentada mas errada* — a classe mais perigosa, porque o dev acha que está seguro.
- **Adoção:** score de confiança por finding, modo `--diff` (só código alterado), supressão, `validate-config`, `--baseline` (gate só nos achados novos) e um dashboard web (React) que lê SARIF.
- **Modelagem de bean/DTO:** getters/setters como contêineres de taint (destrava fluxos que passam por um DTO/command bean), validada a 0 falsos positivos num app de ~126 classes.

---

## O que Torna Este Projeto Confiável

### 1. Benchmark próprio

Um projeto será criado com vulnerabilidades intencionais cobrindo todos os casos suportados — análogo ao DroidBench do FlowDroid. Toda detecção anunciada será validada contra esse benchmark antes do release.

Estrutura planejada:

```
spring-taint-benchmark/
├── sql-injection/
│   ├── direct/          # source → sink na mesma função
│   ├── through-service/ # atravessa service layer
│   └── via-kafka/       # source é @KafkaListener
├── xss/
│   ├── reflected/
│   └── stored/          # cross-request
├── path-traversal/
└── ssrf/
```

### 2. Métricas reportadas honestamente

Cada release reportará:
- **Recall**: % de vulnerabilidades reais detectadas (no benchmark)
- **Precision**: % de alertas que são vulnerabilidades reais (sem falsos positivos)
- Limitações conhecidas documentadas explicitamente

### 3. CVEs reais documentados

O README incluirá CVEs reais de projetos Spring públicos que a ferramenta teria detectado, demonstrando relevância prática — não apenas performance em benchmark artificial.

### 4. Transparência técnica

O approach é documentado: Tai-e + IFDS, o que isso significa em termos de soundness/completeness, quais padrões de código ainda escapam (reflexão, proxies dinâmicos do Spring, etc.).

---

## Extensibilidade

Times podem adicionar suas próprias regras no formato YAML do Tai-e:

```yaml
# custom-taint.yaml
sources:
  # Source customizada: método legado que lê input externo
  - { kind: call,
      method: "<com.myapp.LegacyInput: java.lang.String readUserData()>",
      index: result }

  # Entry point sem call site explícito (ex: listener, callback)
  - { kind: param,
      method: "<com.myapp.EventHandler: void onEvent(java.lang.String)>",
      index: 0 }

sinks:
  - { method: "<com.myapp.LegacyDao: void rawExecute(java.lang.String)>",
      index: 0 }

sanitizers:
  - { method: "<com.myapp.Validator: java.lang.String sanitize(java.lang.String)>",
      index: 0 }
```

---

## Uso

```bash
# Scan básico
spring-taint scan ./meu-projeto

# Com configuração customizada
spring-taint scan --config custom-taint.yaml ./meu-projeto

# Output SARIF (GitHub Advanced Security, GitLab SAST, VS Code)
spring-taint scan --output results.sarif ./meu-projeto

# Filtrar por severidade
spring-taint scan --severity critical,high ./meu-projeto

# Modo verbose — mostra trace completo
spring-taint scan --verbose ./meu-projeto
```

**Output esperado:**

```
[CRITICAL] sql-injection @ GET /users/search
  Source:  UserController.java:12 — @RequestParam String name
  Flow:    UserController → UserService.search() → UserRepository.findByName()
  Sink:    UserRepository.java:34 — JdbcTemplate.execute(query)
  Sanitizer: none detected

[HIGH] xss @ POST /comment + GET /comments
  Source:  CommentController.java:8 — @RequestBody String comment
  Flow:    CommentController → CommentRepository.save() → [DB] → CommentRepository.findAll()
  Sink:    CommentController.java:23 — response.getWriter().write(text)
  Sanitizer: none detected
  Note: stored injection — data persisted across requests
```

**Integração CI — GitHub Actions:**

```yaml
- name: Spring Taint Analysis
  uses: GabrielBBaldez/spring-taint@v0.17.1
  with:
    path: .
    severity: critical,high
    output: results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Stack Técnica

| Componente | Tecnologia | Justificativa |
|---|---|---|
| Linguagem | Java 17+ | Compatibilidade com Tai-e, ecossistema alvo |
| Engine de análise | [Tai-e](https://github.com/pascal-lab/Tai-e) | IFDS nativo, config YAML, ativo, Java 17+ |
| Algoritmo de taint | IFDS via pointer analysis do Tai-e | Interprocedural, flow e context sensitive |
| Output | SARIF 2.1 | Compatível com GitHub, GitLab, VS Code, Azure DevOps |
| Distribuição | CLI binário, Docker, GitHub Action | Integração fácil em qualquer pipeline |
| Build | Maven (projeto principal) + Gradle plugin | Cobertura dos dois ecossistemas |

---

## Limitações Conhecidas (honestidade técnica)

Toda ferramenta de análise estática tem limitações. As deste projeto:

- **Reflexão Java**: fluxos que passam por `Class.forName()` ou `Method.invoke()` podem escapar
- **Proxies dinâmicos do Spring**: AOP e proxies CGLib introduzem indireção que pode quebrar o grafo de chamadas
- **Dados vindos de banco**: stored injection requer modelagem explícita da persistência como propagador
- **Lambdas e method references complexos**: cobertura parcial via suporte do Tai-e
- **Análise cross-service**: dados que atravessam fronteiras de microserviços via HTTP não são rastreados na Fase 1
- **Runtime JDK 17 para o taint (não é limite do bytecode analisado)**: o *processo* da análise de taint roda num runtime JDK 17 -- o tratamento de invokedynamic do Tai-e quebra na biblioteca de runtime do JDK 21. O *app analisado* pode ser compilado com JDK mais novo: recompilar o benchmark pra bytecode Java 21 (major 65) e escanear (num runtime JDK 17) dá resultado idêntico. Os scanners de padrão (`secrets`/`misconfig`/`config`) não têm nenhum limite de JDK.
- **Callbacks de framework**: taint que entra num callback fornecido pelo framework (ex.: o `Connection` passado a `doReturningWork` do Hibernate) ainda não é modelado.

Essas limitações serão documentadas explicitamente em cada release, junto com os casos de teste que as exercitam.

---

## Repositórios

| Repositório | Conteúdo | Status |
|---|---|---|
| `spring-taint` | Engine, CLI, source/sink config, benchmark, dashboard, plugin IntelliJ | ✅ ativo |
| `spring-taint-rules` | Regras adicionais mantidas pela comunidade | 💡 ideia, não criado |
| `quarkus-taint` | Suporte Quarkus / JAX-RS | ⛔ não criado — Quarkus/JAX-RS entraram no repo principal |

---

## Status e Próximos Passos

✅ **Fases 1, 2 e 3 entregues** — engine funcional, benchmark verde, releases públicos até v0.17.0.

- [x] Definição de escopo e posicionamento
- [x] Escolha de engine (Tai-e)
- [x] Mapeamento de gaps vs. concorrentes
- [x] Benchmark inicial: projeto Spring vulnerável com casos documentados (40 casos: 37 vulneráveis, 3 safe)
- [x] Fase 1 MVP: SQL Injection via `@RequestParam` atravessando service/repository
- [x] Fase 1 MVP: XSS via response writer / `@ResponseBody`
- [x] Validação de precision/recall no benchmark (36/37 só com o engine de taint, 0 falsos positivos; 37/37 com a camada near-miss)
- [x] CLI funcional com output SARIF
- [x] Fase 2: `@KafkaListener` **e `@RabbitListener`** como source
- [x] Fase 2: Sanitizers condicionais
- [x] Fase 2: Stored injection cross-request
- [x] GitHub Action
- [x] Release público v0.1.0 (e seguintes, até v0.17.0)
- [x] Validação em apps OSS reais (spring-petclinic, petclinic-rest, sql-injection-web, Contrast) + app de exemplo próprio
- [ ] gRPC / campos Protobuf como source (Fase 3, roadmap)
- [ ] Plugin IntelliJ
- [ ] Publicar imagem no GHCR / Maven Central (quando estável)
