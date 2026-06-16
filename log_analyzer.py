#!/usr/bin/env python3
"""
log_analyzer.py
────────────────────────────────────────────────────────────────────────────
Analisador de logs de acesso HTTP (Apache/Nginx) para identificação de
padrões de ataque, comportamentos anômalos e indicadores de comprometimento.

Detecta:
  - Varreduras de vulnerabilidades (scanners, fuzzing)
  - Tentativas de SQLi, XSS, LFI/RFI, path traversal
  - Força bruta em painéis de login WordPress
  - IPs com volume anômalo de requisições (possível DDoS/bot)
  - Requisições com User-Agent suspeito (ferramentas de ataque)

Uso:
    python3 log_analyzer.py /var/log/apache2/access.log
    python3 log_analyzer.py /var/log/nginx/access.log --top 20 --saida relatorio.txt

Autor: Lygia Teixeira — github.com/lygia-teixeira
"""

import re
import sys
import argparse
import datetime
from pathlib import Path
from collections import defaultdict, Counter

# ── Padrões de ataque ────────────────────────────────────────────────────────

ATTACK_PATTERNS = {
    "SQLi": re.compile(
        r"(union\s+select|select\s+.*from|drop\s+table|insert\s+into|"
        r"1=1|or\s+1=1|and\s+1=1|sleep\s*\(|benchmark\s*\(|"
        r"information_schema|@@version|concat\s*\()",
        re.IGNORECASE
    ),
    "XSS": re.compile(
        r"(<script|javascript:|onerror=|onload=|alert\s*\(|"
        r"document\.cookie|<iframe|<img[^>]+src\s*=\s*['\"]?javascript)",
        re.IGNORECASE
    ),
    "LFI_RFI": re.compile(
        r"(\.\./|\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self|"
        r"php://input|php://filter|data://|expect://|"
        r"http://|https://|ftp://).*\.(php|txt|log)",
        re.IGNORECASE
    ),
    "Path_Traversal": re.compile(
        r"(\.\./){2,}|%2e%2e%2f|%252e%252e|\.\.%2f",
        re.IGNORECASE
    ),
    "WordPress_Brute": re.compile(
        r"POST.*/wp-login\.php",
        re.IGNORECASE
    ),
    "WordPress_Scan": re.compile(
        r"(wp-config\.php|xmlrpc\.php|\.env|/\.git/|/\.htaccess|"
        r"phpinfo\.php|shell\.php|c99\.php|r57\.php|b374k)",
        re.IGNORECASE
    ),
    "Scanner_UA": re.compile(
        r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|"
        r"gobuster|wfuzz|burpsuite|acunetix|nessus|openvas|"
        r"python-requests/[0-9]|curl/[0-9].*bot|go-http-client)",
        re.IGNORECASE
    ),
    "Webshell_Access": re.compile(
        r"(shell\.php|cmd\.php|c99|r57|b374k|wso\.php|"
        r"upload\.php\?cmd=|eval\.php|pass\.php)",
        re.IGNORECASE
    ),
}

# Regex para parsear linha de log Combined Log Format (Apache/Nginx)
LOG_REGEX = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

CORES = {
    "CRÍTICO": "\033[91m",
    "ALTO":    "\033[93m",
    "INFO":    "\033[94m",
    "RESET":   "\033[0m",
    "BOLD":    "\033[1m",
}

# ── Funções ──────────────────────────────────────────────────────────────────

def parsear_log(caminho: str) -> list[dict]:
    """Parseia arquivo de log e retorna lista de entradas."""
    entradas = []
    erros = 0
    with open(caminho, "r", errors="ignore") as f:
        for linha in f:
            m = LOG_REGEX.match(linha.strip())
            if m:
                entradas.append(m.groupdict())
            else:
                erros += 1
    if erros:
        print(f"[!] {erros} linhas não parseadas (formato diferente ou incompleto)")
    return entradas


def detectar_ataques(entradas: list[dict]) -> list[dict]:
    """Aplica padrões de ataque em cada entrada do log."""
    ocorrencias = []
    for e in entradas:
        url_ua = (e.get("url") or "") + " " + (e.get("ua") or "")
        for tipo, regex in ATTACK_PATTERNS.items():
            if regex.search(url_ua):
                ocorrencias.append({
                    "tipo": tipo,
                    "ip": e.get("ip"),
                    "datetime": e.get("datetime"),
                    "method": e.get("method"),
                    "url": (e.get("url") or "")[:100],
                    "status": e.get("status"),
                    "ua": (e.get("ua") or "")[:80],
                })
    return ocorrencias


def analisar_ips(entradas: list[dict], limiar: int = 100) -> dict:
    """Identifica IPs com volume anômalo de requisições."""
    contagem = Counter(e.get("ip") for e in entradas)
    suspeitos = {ip: n for ip, n in contagem.items() if n >= limiar}
    return dict(sorted(suspeitos.items(), key=lambda x: -x[1]))


def analisar_status(entradas: list[dict]) -> dict:
    """Distribução de status HTTP."""
    return dict(Counter(e.get("status") for e in entradas).most_common(15))


def gerar_relatorio(caminho_log, ocorrencias, ips_suspeitos, status_dist,
                    top_n=10, destino=None):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    B = CORES["BOLD"]; R = CORES["RESET"]
    C = CORES["CRÍTICO"]; A = CORES["ALTO"]; I = CORES["INFO"]

    linhas = []
    linhas.append("=" * 70)
    linhas.append(f"  {B}RELATÓRIO DE ANÁLISE DE LOGS — Log Analyzer{R}")
    linhas.append(f"  Arquivo : {caminho_log}")
    linhas.append(f"  Gerado  : {ts}")
    linhas.append(f"  Total de ataques detectados: {C}{len(ocorrencias)}{R}")
    linhas.append("=" * 70)

    # Distribuição por tipo de ataque
    por_tipo = Counter(o["tipo"] for o in ocorrencias)
    linhas.append(f"\n{B}── ATAQUES POR TIPO ──────────────────────────────────{R}")
    for tipo, n in por_tipo.most_common():
        linhas.append(f"  {A}[{tipo}]{R}  {n} ocorrência(s)")

    # IPs suspeitos
    linhas.append(f"\n{B}── IPs COM VOLUME ANÔMALO (≥100 requisições) ─────────{R}")
    if ips_suspeitos:
        for ip, n in list(ips_suspeitos.items())[:top_n]:
            linhas.append(f"  {C}{ip}{R}  →  {n} requisições")
    else:
        linhas.append("  Nenhum IP com volume anômalo detectado.")

    # Status HTTP
    linhas.append(f"\n{B}── DISTRIBUIÇÃO DE STATUS HTTP ───────────────────────{R}")
    for status, n in status_dist.items():
        flag = f"  {C}[suspeito]{R}" if status in ("403", "404", "500") else ""
        linhas.append(f"  HTTP {status}  →  {n}{flag}")

    # Top ocorrências detalhadas
    linhas.append(f"\n{B}── TOP {top_n} OCORRÊNCIAS DETALHADAS ───────────────────{R}")
    for o in ocorrencias[:top_n]:
        linhas.append(f"\n  {C}[{o['tipo']}]{R}")
        linhas.append(f"  IP      : {o['ip']}")
        linhas.append(f"  Data    : {o['datetime']}")
        linhas.append(f"  Método  : {o['method']}  |  Status: {o['status']}")
        linhas.append(f"  URL     : {o['url']}")
        if o['ua']:
            linhas.append(f"  UA      : {o['ua']}")

    linhas.append("\n" + "=" * 70)

    output = "\n".join(linhas)
    print(output)

    if destino:
        limpo = re.sub(r"\033\[[0-9;]*m", "", output)
        Path(destino).write_text(limpo)
        print(f"\n[✓] Relatório salvo em: {destino}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analisador de logs HTTP para detecção de padrões de ataque"
    )
    parser.add_argument("log", help="Caminho do arquivo de log (Apache/Nginx)")
    parser.add_argument("--top", "-n", type=int, default=10,
                        help="Número de ocorrências detalhadas no relatório (default: 10)")
    parser.add_argument("--limiar-ip", type=int, default=100,
                        help="Requisições mínimas para sinalizar IP suspeito (default: 100)")
    parser.add_argument("--saida", "-o", default=None,
                        help="Salvar relatório em arquivo .txt")
    args = parser.parse_args()

    if not Path(args.log).is_file():
        print(f"[ERRO] Arquivo não encontrado: {args.log}")
        sys.exit(1)

    print(f"[*] Parseando log: {args.log}")
    entradas = parsear_log(args.log)
    print(f"[*] Entradas processadas: {len(entradas)}")

    print("[*] Detectando padrões de ataque...")
    ocorrencias = detectar_ataques(entradas)

    print("[*] Analisando IPs...")
    ips_suspeitos = analisar_ips(entradas, args.limiar_ip)

    status_dist = analisar_status(entradas)

    gerar_relatorio(args.log, ocorrencias, ips_suspeitos, status_dist,
                    top_n=args.top, destino=args.saida)


if __name__ == "__main__":
    main()
