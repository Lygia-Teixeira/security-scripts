# 🛡️ Security Scripts

Scripts de segurança desenvolvidos com base em experiência prática em resposta a incidentes, análise de logs e hardening de ambientes WordPress em produção.

> Desenvolvido por [Lygia Teixeira](https://linkedin.com/in/lygia-teixeira) — Blue Team | Incident Response | Hardening

---

## Scripts

### 1. `php_malware_scanner.py` — Scanner de Malware em PHP

Varre recursivamente diretórios em busca de padrões maliciosos em arquivos PHP: backdoors, webshells, injeções ofuscadas com `eval/base64_decode`, Remote File Inclusion e mais.

**Padrões detectados:**
- `eval(base64_decode(...))` — ofuscação clássica de backdoor
- `assert($_POST/GET/REQUEST)` — webshell típico
- `preg_replace` com modificador `/e` — execução arbitrária de código
- Remote File Inclusion via `include/require` com URL externa
- Strings longas em base64 e hex encoding
- `system()`, `exec()`, `shell_exec()`, `passthru()`

```bash
# Varrer diretório WordPress
python3 php_malware_scanner.py /var/www/html/wordpress

# Salvar relatório
python3 php_malware_scanner.py /var/www/html --saida relatorio.txt
```

---

### 2. `log_analyzer.py` — Analisador de Logs HTTP

Analisa logs de acesso Apache/Nginx identificando padrões de ataque, IPs suspeitos e indicadores de comprometimento.

**Detecta:**
- SQLi, XSS, LFI/RFI, Path Traversal
- Força bruta em wp-login.php
- Varreduras com ferramentas conhecidas (Nikto, SQLMap, Nuclei...)
- IPs com volume anômalo de requisições (bots/DDoS)
- Acesso a webshells conhecidas

```bash
# Analisar log Apache
python3 log_analyzer.py /var/log/apache2/access.log

# Top 20 ocorrências + salvar relatório
python3 log_analyzer.py /var/log/nginx/access.log --top 20 --saida relatorio.txt

# Definir limiar de requisições por IP
python3 log_analyzer.py access.log --limiar-ip 50
```

---

### 3. `wp_hardening_check.sh` — Checklist de Hardening WordPress

Checklist automatizado de hardening para ambientes WordPress via terminal Linux. Verifica permissões, configurações críticas, arquivos sensíveis expostos e indicadores de comprometimento.

**Verifica:**
- Permissões de `wp-config.php`, `wp-content/`, `uploads/`
- `WP_DEBUG` em produção
- Prefixo de tabela padrão (`wp_`)
- PHP executável em `/uploads`
- Webshells conhecidas (`c99`, `r57`, `wso`, etc.)
- Arquivos sensíveis expostos (`readme.html`, `xmlrpc.php`, `.env`)
- Versão do WordPress instalada

```bash
chmod +x wp_hardening_check.sh

# Verificar ambiente
./wp_hardening_check.sh /var/www/html/wordpress

# Verificar e corrigir permissões automaticamente
./wp_hardening_check.sh /var/www/html/wordpress --fix
```

---

## Requisitos

**Python scripts:**
```bash
python3 --version  # Python 3.8+
# Sem dependências externas — apenas stdlib
```

**Shell script:**
```bash
# Linux com bash, stat, find, grep
bash --version
```

---

## Contexto

Esses scripts foram desenvolvidos e aplicados em ambiente real de produção com mais de 200 sites WordPress, durante atuação em resposta a incidentes, remoção de malware e hardening de ambientes comprometidos.

---

## Contato

- LinkedIn: [linkedin.com/in/lygia-teixeira](https://linkedin.com/in/lygia-teixeira)
- GitHub: [github.com/lygia-teixeira](https://github.com/lygia-teixeira)
