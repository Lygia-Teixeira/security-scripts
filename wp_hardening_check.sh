#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# wp_hardening_check.sh
# ─────────────────────────────────────────────────────────────────────────────
# Checklist de hardening para ambientes WordPress via linha de comando Linux.
# Verifica permissões de arquivos, configurações críticas, arquivos sensíveis
# expostos e indicadores de comprometimento.
#
# Uso:
#   chmod +x wp_hardening_check.sh
#   ./wp_hardening_check.sh /var/www/html/wordpress
#   ./wp_hardening_check.sh /var/www/html/wordpress --fix   # tenta corrigir permissões
#
# Autor: Lygia Teixeira — github.com/lygia-teixeira
# ─────────────────────────────────────────────────────────────────────────────

# ── Cores ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
BLU='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

PASS="${GRN}[✓ OK]${NC}"
FAIL="${RED}[✗ FALHA]${NC}"
WARN="${YEL}[⚠ AVISO]${NC}"
INFO="${BLU}[i]${NC}"

TOTAL=0; PASSOU=0; FALHOU=0; AVISOS=0
FIX_MODE=false
WP_ROOT=""

# ── Argumentos ───────────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --fix) FIX_MODE=true ;;
        *) WP_ROOT="$arg" ;;
    esac
done

if [[ -z "$WP_ROOT" || ! -d "$WP_ROOT" ]]; then
    echo -e "${RED}[ERRO]${NC} Informe o caminho do WordPress: $0 /caminho/wordpress"
    exit 1
fi

WP_ROOT="${WP_ROOT%/}"

# ── Funções auxiliares ────────────────────────────────────────────────────────
check() {
    local desc="$1"; local result="$2"; local fix_msg="$3"
    TOTAL=$((TOTAL+1))
    if [[ "$result" == "ok" ]]; then
        echo -e "  $PASS $desc"
        PASSOU=$((PASSOU+1))
    elif [[ "$result" == "warn" ]]; then
        echo -e "  $WARN $desc"
        [[ -n "$fix_msg" ]] && echo -e "       ${YEL}→ $fix_msg${NC}"
        AVISOS=$((AVISOS+1))
    else
        echo -e "  $FAIL $desc"
        [[ -n "$fix_msg" ]] && echo -e "       ${RED}→ $fix_msg${NC}"
        FALHOU=$((FALHOU+1))
    fi
}

section() { echo -e "\n${BOLD}${BLU}── $1 ─────────────────────────────────────${NC}"; }

# ── Início ────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  WordPress Hardening Check — Lygia Teixeira${NC}"
echo -e "${BOLD}  Alvo: ${WP_ROOT}${NC}"
echo -e "${BOLD}  Data: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
$FIX_MODE && echo -e "${YEL}  Modo --fix ativado: tentará corrigir permissões${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"

# ── 1. Verificação de arquivos críticos ──────────────────────────────────────
section "ARQUIVOS CRÍTICOS"

# wp-config.php existe
if [[ -f "$WP_ROOT/wp-config.php" ]]; then
    check "wp-config.php encontrado" "ok"

    # Permissão do wp-config.php
    perm=$(stat -c "%a" "$WP_ROOT/wp-config.php" 2>/dev/null)
    if [[ "$perm" == "400" || "$perm" == "440" || "$perm" == "600" ]]; then
        check "wp-config.php permissão ($perm)" "ok"
    else
        check "wp-config.php permissão ($perm) — deve ser 400, 440 ou 600" "fail" \
              "chmod 440 $WP_ROOT/wp-config.php"
        $FIX_MODE && chmod 440 "$WP_ROOT/wp-config.php" && \
            echo -e "     ${GRN}[fix] Permissão corrigida para 440${NC}"
    fi

    # Prefixo de tabela padrão
    if grep -q "table_prefix.*'wp_'" "$WP_ROOT/wp-config.php"; then
        check "Prefixo de tabela padrão 'wp_' detectado (risco de SQLi)" "warn" \
              "Altere o prefixo no banco de dados e no wp-config.php"
    else
        check "Prefixo de tabela personalizado" "ok"
    fi

    # Debug mode
    if grep -q "WP_DEBUG.*true" "$WP_ROOT/wp-config.php"; then
        check "WP_DEBUG está ativado — expõe erros PHP" "fail" \
              "Defina WP_DEBUG como false em produção"
    else
        check "WP_DEBUG desativado" "ok"
    fi
else
    check "wp-config.php não encontrado em $WP_ROOT" "warn" \
          "Verifique se o caminho informado é a raiz do WordPress"
fi

# .htaccess
if [[ -f "$WP_ROOT/.htaccess" ]]; then
    check ".htaccess presente" "ok"
    if grep -q "Options -Indexes" "$WP_ROOT/.htaccess"; then
        check "Listagem de diretórios desabilitada (Options -Indexes)" "ok"
    else
        check "Listagem de diretórios pode estar habilitada" "warn" \
              "Adicione 'Options -Indexes' ao .htaccess"
    fi
else
    check ".htaccess ausente" "warn" "Crie o .htaccess com configurações de segurança básicas"
fi

# ── 2. Permissões de diretórios ───────────────────────────────────────────────
section "PERMISSÕES DE DIRETÓRIOS"

check_dir_perm() {
    local dir="$1"; local esperado="$2"
    if [[ ! -d "$dir" ]]; then return; fi
    local perm
    perm=$(stat -c "%a" "$dir" 2>/dev/null)
    if [[ "$perm" == "$esperado" ]]; then
        check "$(basename $dir)/ permissão ($perm)" "ok"
    else
        check "$(basename $dir)/ permissão ($perm) — esperado $esperado" "fail" \
              "chmod $esperado $dir"
        $FIX_MODE && chmod "$esperado" "$dir" && \
            echo -e "     ${GRN}[fix] Permissão corrigida para $esperado${NC}"
    fi
}

check_dir_perm "$WP_ROOT/wp-content" "755"
check_dir_perm "$WP_ROOT/wp-content/uploads" "755"
check_dir_perm "$WP_ROOT/wp-includes" "755"
check_dir_perm "$WP_ROOT/wp-admin" "755"

# PHP executável em uploads
if [[ -d "$WP_ROOT/wp-content/uploads" ]]; then
    php_in_uploads=$(find "$WP_ROOT/wp-content/uploads" -name "*.php" 2>/dev/null | head -5)
    if [[ -n "$php_in_uploads" ]]; then
        check "Arquivos PHP encontrados em wp-content/uploads!" "fail" \
              "Remova imediatamente: $php_in_uploads"
    else
        check "Nenhum arquivo PHP em wp-content/uploads" "ok"
    fi
fi

# ── 3. Arquivos suspeitos ─────────────────────────────────────────────────────
section "ARQUIVOS SUSPEITOS"

SHELLS=("shell.php" "c99.php" "r57.php" "wso.php" "b374k.php" "cmd.php" "eval.php" "upload.php")
found_shell=false
for shell in "${SHELLS[@]}"; do
    resultado=$(find "$WP_ROOT" -name "$shell" 2>/dev/null)
    if [[ -n "$resultado" ]]; then
        check "Webshell detectada: $shell" "fail" "Remova: $resultado"
        found_shell=true
    fi
done
$found_shell || check "Nenhuma webshell conhecida detectada" "ok"

# Arquivos PHP em uploads (busca ampla)
php_uploads_count=$(find "$WP_ROOT/wp-content/uploads" -name "*.php" 2>/dev/null | wc -l)
if [[ "$php_uploads_count" -gt 0 ]]; then
    check "$php_uploads_count arquivo(s) PHP em uploads" "fail" \
          "find $WP_ROOT/wp-content/uploads -name '*.php' -delete"
else
    check "Sem arquivos PHP em uploads" "ok"
fi

# ── 4. Exposição de arquivos sensíveis ───────────────────────────────────────
section "EXPOSIÇÃO DE ARQUIVOS SENSÍVEIS"

SENSIVEIS=("readme.html" "license.txt" "wp-config-sample.php" "xmlrpc.php" ".env")
for arq in "${SENSIVEIS[@]}"; do
    if [[ -f "$WP_ROOT/$arq" ]]; then
        if [[ "$arq" == "xmlrpc.php" ]]; then
            check "xmlrpc.php presente — vetor comum de brute force e DDoS" "warn" \
                  "Bloqueie via .htaccess ou plugin se não utilizado"
        else
            check "$arq presente — pode expor informações" "warn" \
                  "Remova ou bloqueie acesso: rm $WP_ROOT/$arq"
        fi
    fi
done

# ── 5. Versão do WordPress ────────────────────────────────────────────────────
section "VERSÃO E ATUALIZAÇÕES"

VERSION_FILE="$WP_ROOT/wp-includes/version.php"
if [[ -f "$VERSION_FILE" ]]; then
    WP_VER=$(grep "wp_version\s*=" "$VERSION_FILE" | head -1 | grep -oP "[\d.]+")
    check "Versão do WordPress detectada: $WP_VER" "warn" \
          "Verifique se $WP_VER é a versão mais recente em wordpress.org"
fi

# readme.html expõe versão
if [[ -f "$WP_ROOT/readme.html" ]]; then
    check "readme.html expõe versão do WordPress publicamente" "fail" \
          "rm $WP_ROOT/readme.html"
fi

# ── Resumo ────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMO${NC}"
echo -e "  Total de verificações : $TOTAL"
echo -e "  ${GRN}Passou${NC}               : $PASSOU"
echo -e "  ${YEL}Avisos${NC}               : $AVISOS"
echo -e "  ${RED}Falhou${NC}               : $FALHOU"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}\n"

if [[ $FALHOU -gt 0 ]]; then
    echo -e "${RED}[!] Ambiente com problemas críticos de segurança. Corrija antes de produção.${NC}\n"
    exit 2
elif [[ $AVISOS -gt 0 ]]; then
    echo -e "${YEL}[⚠] Ambiente com pontos de atenção. Revise os avisos acima.${NC}\n"
    exit 1
else
    echo -e "${GRN}[✓] Ambiente com hardening básico adequado.${NC}\n"
    exit 0
fi
