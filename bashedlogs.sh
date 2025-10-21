#!/usr/bin/env bash
# bashedlogs.sh - Enhanced Cybersecurity Log Analyzer
# Author: Enhanced version for comprehensive log analysis
# Usage: ./bashedlogs.sh [logfile] [format]

set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BROWN='\033[38;5;94m'  # Darker brown
GRAY='\033[0;90m'
BLACK='\033[0;30m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Display ASCII banner
show_banner() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} "
    echo -e "${CYAN}║${NC}   ${BROWN}   ,___,${NC}"
    echo -e "${CYAN}║${NC}   ${BROWN}   [${NC}${YELLOW}O${NC}${BROWN}.${NC}${YELLOW}o${NC}${BROWN}]${NC}        ${BOLD}${WHITE}CYBERSECURITY LOG ANALYSIS TOOL${NC}"
    echo -e "${CYAN}║${NC}   ${BROWN}   /)__)${NC}"
    echo -e "${CYAN}║${NC}   ${GRAY}  ${NC}${BLACK}-${NC}${YELLOW}\"${NC}${BLACK}--${NC}${YELLOW}\"${NC}${BLACK}-${NC}"
    echo -e "${CYAN}║${NC} "
    echo -e "${CYAN}║${NC}                                                ${BOLD}${WHITE}Author: talons${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}SSH | Login | FTP | Web | SQLite | Proxy | Payments | VPN${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}Firewall | IDS/IPS | Email | Database | Docker | Kubernetes${NC}"
    echo -e "${CYAN}║${NC}   ${GREEN}Route53 | IoT | Android | NGINX | SSHD | WAF | + Generic${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
}

# Print usage information
print_usage() {
    show_banner
    echo
    echo -e "${WHITE}A fast CLI to auto-detect and analyze many security log formats.${NC}"
    echo -e "${WHITE}Outputs rich metrics and a security assessment for the provided log file.${NC}"
    echo
    echo -e "${BOLD}${YELLOW}Usage:${NC}"
    echo -e "  ${CYAN}./bashedlogs.sh start${NC}                    - Interactive mode with splash page"
    echo -e "  ${CYAN}./bashedlogs.sh <logfile> [format]${NC}       - Direct analysis (auto-detect or explicit)"
    echo
    echo -e "${BOLD}${YELLOW}Examples:${NC}"
    echo -e "  ${CYAN}./bashedlogs.sh start${NC}                    - Start interactive mode"
    echo -e "  ${CYAN}./bashedlogs.sh auth.log${NC}                 - Auto-detect and analyze"
    echo -e "  ${CYAN}./bashedlogs.sh auth.log auth_ssh${NC}        - Analyze as SSH/Auth log"
    echo -e "  ${CYAN}./bashedlogs.sh access.log access_log${NC}    - Analyze as Apache/NGINX log"
    echo -e "  ${CYAN}./bashedlogs.sh route53.log auto${NC}         - Explicit auto-detect"
    echo
}

# Print supported formats table
print_supported_formats() {
    local formats=(
        "auth_ssh" "devices" "access_log" "syslog" "route53"
        "android_system" "login_attempts" "sqlite" "vsftpd"
        "squid" "payments" "csv"
    )
    
    echo -e "${BOLD}${YELLOW}Unique Log Analyses:${NC}"
    echo -e "${CYAN}┌────────────────────────┬────────────────────────┬────────────────────────┬────────────────────────┐${NC}"
    
    local cols=4
    local colw=24
    local i=0
    local line=""
    
    for f in "${formats[@]}"; do
        printf -v cell "%-${colw}s" "$f"
        line+="$cell"
        i=$((i+1))
        if (( i % cols == 0 )); then
            echo -e "${CYAN}│${NC} ${line}${CYAN}│${NC}"
            line=""
        fi
    done
    
    # Handle remaining formats if not divisible by cols
    if [[ -n "$line" ]]; then
        while (( i % cols != 0 )); do
            printf -v cell "%-${colw}s" ""
            line+="$cell"
            i=$((i+1))
        done
        echo -e "${CYAN}│${NC} ${line}${CYAN}│${NC}"
    fi
    
    echo -e "${CYAN}└────────────────────────┴────────────────────────┴────────────────────────┴────────────────────────┘${NC}"
    echo -e "${GRAY} *Fallback feature will run generic log analysis if specific log format is not recognized.${NC}"
    echo
}

# Show splash page with description and formats
show_splash() {
    show_banner
    echo
    echo -e "${WHITE}${BOLD}Description:${NC}"
    echo -e "${WHITE}Analyze security logs across SSH, Web, DNS, Firewall, IDS/IPS, Email, VPN, Database,${NC}"
    echo -e "${WHITE}Docker, Kubernetes, Android, IoT devices, and more. Auto-detects log format or accepts${NC}"
    echo -e "${WHITE}explicit format specification. Outputs detailed statistics and security risk assessment.${NC}"
    echo
    print_supported_formats
    echo -e "${BOLD}${YELLOW}Basic Usage:${NC}"
    echo -e "  ${CYAN}Explicit format:${NC}   ./bashedlogs.sh ${MAGENTA}<logfile>${NC} ${YELLOW}<format>${NC}"
    echo -e "  ${CYAN}Auto-detect:${NC}       ./bashedlogs.sh ${MAGENTA}<logfile>${NC} ${YELLOW}auto${NC}"
    echo -e "  ${CYAN}Auto-detect:${NC}       ./bashedlogs.sh ${MAGENTA}<logfile>${NC}"
    echo
}

# Run analysis based on format
run_analysis() {
    local file="$1"
    local format="${2:-auto}"
    
    if [[ -z "$file" || ! -f "$file" ]]; then
        echo -e "${RED}Error: Please provide a valid log file path.${NC}"
        return 1
    fi
    
    # Auto-detect format if needed
    if [[ "$format" == "auto" ]]; then
        format="$(detect_format "$file" || echo "generic")"
        format="${format:-generic}"
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${NC} ${BOLD}${WHITE}Auto-detected format: ${YELLOW}${format}${NC} ${CYAN}║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo
    fi
    
    # Route to appropriate analyzer
    case "$format" in
        route53) analyze_route53 "$file" ;;
        devices) analyze_devices "$file" ;;
        android_system) analyze_android_system "$file" ;;
        access_log) analyze_apache "$file" ;;
        syslog) analyze_syslog "$file" ;;
        auth_ssh) analyze_auth_ssh "$file" ;;
        login_attempts) analyze_login_attempts "$file" ;;
        sqlite) analyze_sqlite "$file" ;;
        payments) analyze_payments "$file" ;;
        vsftpd) analyze_vsftpd "$file" ;;
        squid) analyze_squid "$file" ;;
        nginx_error|firewall_*|ids_*|windows_event|email_*|vpn_*|database_*|docker|kubernetes|loadbalancer_haproxy|waf_*|dhcp|json|csv|generic)
            analyze_generic_security "$file" "$format"
            ;;
        *)
            echo -e "${YELLOW}Unknown format '${format}' - using generic analyzer${NC}"
            analyze_generic_security "$file" "$format"
            ;;
    esac
}

# Interactive start flow
handle_start() {
    show_splash
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}Interactive Mode${NC}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    read -r -p "$(echo -e "${CYAN}Enter path to log file:${NC} ")" user_file
    
    if [[ -z "$user_file" ]]; then
        echo -e "${RED}Error: No file provided.${NC}"
        return 1
    fi
    
    if [[ ! -f "$user_file" ]]; then
        echo -e "${RED}Error: File '${user_file}' does not exist.${NC}"
        return 1
    fi
    
    read -r -p "$(echo -e "${CYAN}Enter format (press Enter for auto-detect):${NC} ")" user_fmt
    user_fmt="${user_fmt:-auto}"
    
    echo
    echo -e "${GREEN}Starting analysis...${NC}"
    echo
    
    run_analysis "$user_file" "$user_fmt"
}



# Print colored section headers
print_header() {
    local title="$1"
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC} ${WHITE}${title}${NC} ${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
}

# Print formatted results
print_result() {
    local label="$1"
    local value="$2"
    local color="${3:-$GREEN}"
    printf "  ${BOLD}%-50s${NC} ${color}%s${NC}\n" "$label:" "$value"
}

# Print statistics in a table format
print_stats_table() {
    local title="$1"
    shift
    echo -e "${YELLOW}  $title${NC}"
    echo -e "${CYAN}  ┌────────────────────────────────────────────────────────────────┐${NC}"
    while [[ $# -gt 0 ]]; do
        printf "${CYAN}  │${NC} %-62s ${CYAN}│${NC}\n" "$1"
        shift
    done
    echo -e "${CYAN}  └────────────────────────────────────────────────────────────────┘${NC}"
}

# Enhanced format detection with better patterns
detect_format() {
    local file="$1"
    local sample_size=20
    
    # Check if it's a SQLite database
    if file "$file" | grep -q "SQLite"; then
        echo "sqlite"
        return
    fi
    
    # Check first several lines for format detection
    head -"$sample_size" "$file" | while read -r line; do
        case "$line" in
            # Route53 format: version timestamp hosted_zone domain...
            "1.0 "[0-9][0-9][0-9][0-9]-*) echo "route53"; return ;;
            
    # SSH/Auth logs: sshd[PID]: pattern or PAM authentication
            *"sshd["*"]"*|*"PAM"*"authentication"*) echo "auth_ssh"; return ;;
            
            # PayPal SOAP/API payment logs (PayPal SDK)
            *"PPAPIService:"*|*"PPHttpConnection:"*|*"PayPalAPI"*|*"X-PAYPAL-"*|*"<soapenv:Envelope"*) echo "payments"; return ;;
            
            # Device logs: Look for device type patterns (check before date patterns to avoid false positives)
            *"TEMPERATURE_SENSOR"*|*"MOTION_SENSOR"*|*"LIGHT"*|*"POWER_METER"*) echo "devices"; return ;;
            
            # Login logs: username:password combination patterns
            *":"*":"*":"*":"*) 
                if echo "$line" | grep -q "^[a-zA-Z0-9_]*:[^:]*:[0-9.]*"; then
                    echo "login_attempts"; return
                fi
                ;;
            
            # Tab-separated login logs: date timestamp IP username
            [0-9][0-9][0-9][0-9]"-"[0-9][0-9]"-"[0-9][0-9]*[0-9][0-9]":"[0-9][0-9]":"[0-9][0-9]*)
                if echo "$line" | grep -qE $'\t[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\t'; then
                    echo "login_attempts"; return
                fi
                ;;
            
            # VSFTPD logs: Day Mon DD HH:MM:SS YYYY [pid N] [username]
            [A-Z][a-z][a-z]" "[A-Z][a-z][a-z]" "[0-9]*" "[0-9][0-9]":"[0-9][0-9]":"[0-9][0-9]*"[pid "*) echo "vsftpd"; return ;;
            
            # Squid proxy logs: timestamp elapsed client action/code size method URL
            [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"."[0-9]*" "*"TCP_"*) echo "squid"; return ;;
            
            # Payment logs: transaction ID patterns
            *"transaction_id"*|*"txn_id"*|*"payment"*|*"purchase"*)
                if echo "$line" | grep -q "^[0-9]\+,"; then
                    echo "payments"; return
                fi
                ;;
            
            # Android system logs: MM-DD HH:MM:SS.mmm  PID TID LEVEL TAG: message
            [0-9][0-9]"-"[0-9][0-9]*[0-9][0-9]":"[0-9][0-9]":"[0-9][0-9]"."[0-9][0-9][0-9]*[DWIEV]*) echo "android_system"; return ;;
            
            # Beginning of log markers
            "--------- beginning of"*) echo "android_system"; return ;;
            
            # Apache/NGINX access logs: IP - - [timestamp] "METHOD /path HTTP/1.x" status size
            *" - - ["*"] \""*"\" "[0-9]*) echo "access_log"; return ;;
            [0-9][0-9][0-9][0-9]"/"[0-9][0-9]"/"[0-9][0-9]*"["*"]"*"#"*) echo "nginx_error"; return ;;
            
            # Firewall logs: iptables, pfSense, ASA
            *"kernel:"*"["*"]"*"IN="*"OUT="*) echo "firewall_iptables"; return ;;
            *"filterlog:"*) echo "firewall_pfsense"; return ;;
            *"%ASA-"*|*"%FWSM-"*) echo "firewall_cisco"; return ;;
            
            # IDS/IPS logs: Snort, Suricata
            *"[Priority:"*"]"*"[Classification:"*) echo "ids_snort"; return ;;
            *"["*":"*":"*"]"*"[Classification:"*) echo "ids_suricata"; return ;;
            
            # Windows Event logs
            *"EventID"*|*"Event ID:"*|*"EventCode"*) echo "windows_event"; return ;;
            
            # Email logs: Postfix, Exchange
            *"postfix/"*) echo "email_postfix"; return ;;
            *"SMTP"*"from=<"*">"*) echo "email_smtp"; return ;;
            
            # VPN logs: OpenVPN
            *"VERIFY"*"OK"*"depth="*|*"TLS:"*) echo "vpn_openvpn"; return ;;
            
            # Database logs: MySQL, PostgreSQL, MongoDB
            *"[Note]"*"InnoDB"*|*"mysqld"*) echo "database_mysql"; return ;;
            *"LOG:"*"database"*|*"ERROR:"*"database"*) echo "database_postgresql"; return ;;
            *"[conn"*"]"*"command:"*) echo "database_mongodb"; return ;;
            
            # Docker logs
            *"container"*"name="*|*"docker"*"container_id="*) echo "docker"; return ;;
            
            # Kubernetes logs
            *"kube-apiserver"*|*"kubelet"*|*"kube-proxy"*) echo "kubernetes"; return ;;
            
            # HAProxy load balancer
            *"haproxy["*"]"*"backend"*"server"*) echo "loadbalancer_haproxy"; return ;;
            
            # ModSecurity WAF
            *"ModSecurity:"*|*"[id \""*"\"]"*"[msg \""*) echo "waf_modsecurity"; return ;;
            
            # DHCP logs
            *"DHCPACK"*|*"DHCPREQUEST"*|*"DHCPOFFER"*) echo "dhcp"; return ;;
            
            # Generic patterns
            [A-Z][a-z][a-z]" "[0-9]*" "[0-9][0-9]":"*) echo "syslog"; return ;;
            "{"*"}"*) echo "json"; return ;;
            *","*","*) echo "csv"; return ;;
            *) continue ;;
        esac
    done | head -1
}

# Route53 DNS log analysis with comprehensive metrics
analyze_route53() {
    local file="$1"
    print_header "ROUTE53 DNS LOG ANALYSIS"
    
    # Basic metrics
    local total_requests=$(grep -v '^#\|^$' "$file" | wc -l)
    print_result "Total DNS Requests" "$total_requests"
    
    # Top Resolver IPs
    echo -e "\n${YELLOW}Top Resolver IPs:${NC}"
    (grep -v '^#\|^$' "$file" | awk '{print $9}' | sort | uniq -c | sort -nr | head -10 || true) | \
    while read count ip; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$ip" "$count"
    done
    
    # Top Client Subnets
    echo -e "\n${YELLOW}Top Client Subnets:${NC}"
    local subnet_data=$(grep -v '^#\|^$' "$file" | awk '$11 != "-" {print $11}' | sort | uniq -c | sort -nr | head -10)
    if [[ -n "$subnet_data" ]]; then
        echo "$subnet_data" | while read count subnet; do
            printf "  ${GREEN}%-50s${NC} %s requests\n" "$subnet" "$count"
        done
    else
        printf "  ${RED}No client subnet data found${NC}\n"
    fi
    
    # Busiest Minute
    echo -e "\n${YELLOW}Busiest Minute:${NC}"
    local busiest_minute_data=$(grep -v '^#\|^$' "$file" | awk '{print substr($2,1,16)}' | sort | uniq -c | sort -nr | head -1)
    if [[ -n "$busiest_minute_data" ]]; then
        local busiest_count=$(echo "$busiest_minute_data" | awk '{print $1}')
        local busiest_minute=$(echo "$busiest_minute_data" | awk '{print $2}')
        print_result "Peak Activity Time" "$busiest_minute ($busiest_count requests)"
        
        # Show top 10 busiest minutes
        echo
        (grep -v '^#\|^$' "$file" | awk '{print substr($2,1,16)}' | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count minute; do
            printf "  ${CYAN}%-50s${NC} %s requests\n" "$minute" "$count"
        done
    else
        printf "  ${RED}No timestamp data found${NC}\n"
    fi
    
    # Domain Rankings
    echo -e "\n${YELLOW}Domain Rankings:${NC}"
    local domain_stats=$(grep -v '^#\|^$' "$file" | awk '{print $4}' | sort | uniq -c | sort -n)
    local total_domains=$(echo "$domain_stats" | wc -l | tr -d ' ')
    print_result "Total Unique Domains" "$total_domains"
    
    # Least requested domains
    echo -e "\n${YELLOW}Least Requested Domains:${NC}"
    (echo "$domain_stats" | head -10 || true) | \
    while read count domain; do
        printf "  ${CYAN}%-50s${NC} %s requests\n" "$domain" "$count"
    done
    
    # Most requested domains
    echo -e "\n${YELLOW}Most Requested Domains:${NC}"
    (echo "$domain_stats" | sort -nr | head -10 || true) | \
    while read count domain; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$domain" "$count"
    done
    
    # Busiest Cities
    echo -e "\n${YELLOW}Busiest Cities:${NC}"
    local city_analysis=$(grep -v '^#\|^$' "$file" | awk '{
        # Look for city patterns in domains and IPs
        if ($4 ~ /seattle|portland|vancouver|phoenix|denver|dallas|chicago|atlanta|miami|nyc|newyork|boston|dc|washington/) {
            if (match($4, /seattle/)) print "seattle"
            else if (match($4, /portland/)) print "portland"
            else if (match($4, /vancouver/)) print "vancouver"
            else if (match($4, /phoenix/)) print "phoenix"
            else if (match($4, /denver/)) print "denver"
            else if (match($4, /dallas/)) print "dallas"
            else if (match($4, /chicago/)) print "chicago"
            else if (match($4, /atlanta/)) print "atlanta"
            else if (match($4, /miami/)) print "miami"
            else if (match($4, /nyc/)) print "nyc"
            else if (match($4, /newyork/)) print "newyork"
            else if (match($4, /boston/)) print "boston"
            else if (match($4, /dc/)) print "dc"
            else if (match($4, /washington/)) print "washington"
        }
        # Also check resolver IPs for geographic patterns
        if ($9 ~ /^(192\.168\.|10\.|172\.)/) {
            print "Local-Network"
        } else if ($9 ~ /^8\.8\./) {
            print "Google-DNS"
        } else if ($9 ~ /^1\.1\./) {
            print "Cloudflare-DNS"
        }
    }' | sort | uniq -c | sort -nr)
    
    if [[ -n "$city_analysis" ]]; then
        (echo "$city_analysis" | head -10 || true) | \
        while read count city; do
            # Map city codes to full names
            case "$city" in
                "nyc"|"newyork") city_name="New York" ;;
                "dc"|"washington") city_name="Washington DC" ;;
                "seattle") city_name="Seattle" ;;
                "portland") city_name="Portland" ;;
                "vancouver") city_name="Vancouver" ;;
                "phoenix") city_name="Phoenix" ;;
                "denver") city_name="Denver" ;;
                "dallas") city_name="Dallas" ;;
                "chicago") city_name="Chicago" ;;
                "atlanta") city_name="Atlanta" ;;
                "miami") city_name="Miami" ;;
                "boston") city_name="Boston" ;;
                "Local-Network") city_name="Local Network" ;;
                "Google-DNS") city_name="Google DNS" ;;
                "Cloudflare-DNS") city_name="Cloudflare DNS" ;;
                *) city_name="$city" ;;
            esac
            printf "  ${GREEN}%-50s${NC} %s requests\n" "$city_name" "$count"
        done
    else
        # Alternative approach - geographic patterns
        local geo_patterns=$(grep -v '^#\|^$' "$file" | awk '{
            if ($4 ~ /\.uk$/) print "United Kingdom"
            else if ($4 ~ /\.ca$/) print "Canada"
            else if ($4 ~ /\.au$/) print "Australia"
            else if ($4 ~ /\.de$/) print "Germany"
            else if ($4 ~ /\.fr$/) print "France"
            else if ($4 ~ /\.jp$/) print "Japan"
            else if ($4 ~ /amazonaws\.com/) print "AWS-Global"
            else if ($4 ~ /cloudfront\.net/) print "CloudFront-Global"
            else if ($4 ~ /googleusercontent\.com/) print "Google-Global"
            else print "Other-Locations"
        }' | sort | uniq -c | sort -nr)
        
        if [[ -n "$geo_patterns" ]]; then
            (echo "$geo_patterns" | head -10 || true) | \
            while read count location; do
                printf "  ${GREEN}%-50s${NC} %s requests\n" "$location" "$count"
            done
        else
            printf "  ${RED}No geographic data detected${NC}\n"
        fi
    fi
    
    # Cloud Regions
    echo -e "\n${YELLOW}Cloud Regions:${NC}"
    local region_analysis=$(grep -v '^#\|^$' "$file" | awk '{
        # AWS regions
        region_start = match($4, /[a-z]{2}-[a-z]+-[0-9]+/)
        if (region_start > 0) {
            region = substr($4, region_start, RLENGTH)
            # Map to state if US region
            if (region ~ /^us-east-1/) print region " (Virginia)"
            else if (region ~ /^us-east-2/) print region " (Ohio)"
            else if (region ~ /^us-west-1/) print region " (California)"
            else if (region ~ /^us-west-2/) print region " (Oregon)"
            else if (region ~ /^ca-central-1/) print region " (Canada)"
            else if (region ~ /^eu-west-1/) print region " (Ireland)"
            else if (region ~ /^eu-central-1/) print region " (Germany)"
            else if (region ~ /^ap-southeast-1/) print region " (Singapore)"
            else if (region ~ /^ap-northeast-1/) print region " (Japan)"
            else print region
        }
        # Look for other cloud patterns
        else if ($4 ~ /\.azure/) print "Azure-Global"
        else if ($4 ~ /\.googleusercontent\.com/) print "Google-Cloud"
        else if ($4 ~ /\.cloudfront\.net/) print "CloudFront-Global"
        else if ($4 ~ /\.amazonaws\.com/) print "AWS-Global"
    }' | sort | uniq -c | sort -nr)
    
    if [[ -n "$region_analysis" ]]; then
        (echo "$region_analysis" | head -10 || true) | \
        while read count region_info; do
            printf "  ${GREEN}%-50s${NC} %s requests\n" "$region_info" "$count"
        done
    else
        printf "  ${RED}No cloud regions detected${NC}\n"
    fi
    
    # Query type analysis
    echo -e "\n${YELLOW}DNS Query Types:${NC}"
    (grep -v '^#\|^$' "$file" | awk '{print $5}' | sort | uniq -c | sort -nr | head -10 || true) | \
    while read count qtype; do
        printf "  ${CYAN}%-50s${NC} %s queries\n" "$qtype" "$count"
    done
    
    # Response status analysis
    echo -e "\n${YELLOW}DNS Response Status:${NC}"
    grep -v '^#\|^$' "$file" | awk '{print $6}' | sort | uniq -c | sort -nr | \
    while read count status; do
        if [[ "$status" == "NOERROR" ]]; then
            printf "  ${GREEN}%-50s${NC} %s responses\n" "$status" "$count"
        else
            printf "  ${RED}%-50s${NC} %s responses\n" "$status" "$count"
        fi
    done
    
    # CYBERSECURITY THREAT ANALYSIS
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    echo
    # DNS Security Analysis
    local nxdomain_count=$(grep -v '^#\|^$' "$file" | awk '$6 == "NXDOMAIN"' | wc -l | tr -d ' ')
    local servfail_count=$(grep -v '^#\|^$' "$file" | awk '$6 == "SERVFAIL"' | wc -l | tr -d ' ')
    local noerror_count=$(grep -v '^#\|^$' "$file" | awk '$6 == "NOERROR"' | wc -l | tr -d ' ')
    local unique_resolvers=$(grep -v '^#\|^$' "$file" | awk '{print $9}' | sort -u | wc -l | tr -d ' ')
    
    echo -e "${YELLOW}DNS Security Summary:${NC}"
    print_result "Successful Queries (NOERROR)" "${noerror_count}" "$GREEN"
    print_result "Failed Queries (NXDOMAIN)" "${nxdomain_count}" "$RED"
    print_result "Server Failures (SERVFAIL)" "${servfail_count}" "$RED"
    print_result "Unique Resolver IPs" "${unique_resolvers}" "$CYAN"
    
    # Calculate security score
    local security_score=0
    local fail_ratio=0
    if [[ $total_requests -gt 0 ]]; then
        fail_ratio=$(echo "scale=2; ($nxdomain_count + $servfail_count) * 100 / $total_requests" | bc 2>/dev/null || echo "0")
    fi
    
    echo -e "\n${YELLOW}DNS Pattern Analysis:${NC}"
    print_result "Query Failure Rate" "${fail_ratio}%" "$YELLOW"
    
    # Detect potential DNS tunneling or exfiltration
    local long_domains=$(grep -v '^#\|^$' "$file" | awk 'length($4) > 50' | wc -l | tr -d ' ')
    print_result "Long Domain Names (>50 chars)" "${long_domains}" "$YELLOW"
    
    # Unusual query patterns
    local txt_queries=$(grep -v '^#\|^$' "$file" | awk '$5 == "TXT"' | wc -l | tr -d ' ')
    local ptr_queries=$(grep -v '^#\|^$' "$file" | awk '$5 == "PTR"' | wc -l | tr -d ' ')
    print_result "TXT Record Queries" "${txt_queries}"
    print_result "PTR Record Queries" "${ptr_queries}"
    
    # Overall risk assessment
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    
    # Calculate risk based on metrics
    if [[ $(echo "$fail_ratio > 20" | bc 2>/dev/null || echo 0) -eq 1 ]] || [[ $long_domains -gt 100 ]]; then
        security_score=50
    elif [[ $(echo "$fail_ratio > 10" | bc 2>/dev/null || echo 0) -eq 1 ]] || [[ $long_domains -gt 20 ]]; then
        security_score=25
    else
        security_score=5
    fi
    
    if [[ $security_score -gt 40 ]]; then
        print_result "Risk Level" "HIGH - Unusual DNS patterns detected" "$RED"
        echo -e "\n${RED}  ⚠️  HIGH RISK INDICATORS:${NC}"
        echo -e "${RED}     • Elevated query failure rate (${fail_ratio}%)${NC}"
        echo -e "${RED}     • Review for DNS tunneling or exfiltration${NC}"
        echo -e "${RED}     • Monitor resolver behavior patterns${NC}"
    elif [[ $security_score -gt 15 ]]; then
        print_result "Risk Level" "MEDIUM - Moderate DNS activity" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY:${NC}"
        echo -e "${CYAN}     • Normal DNS operation with some anomalies${NC}"
        echo -e "${CYAN}     • Continue standard monitoring${NC}"
    else
        print_result "Risk Level" "LOW - Normal DNS operation" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION:${NC}"
        echo -e "${GREEN}     • DNS queries within expected parameters${NC}"
        echo -e "${GREEN}     • No significant security concerns${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $nxdomain_count -gt 1000 ]]; then
        echo -e "${YELLOW}  🔍 High NXDOMAIN count - investigate potential DNS enumeration${NC}"
    fi
    if [[ $long_domains -gt 50 ]]; then
        echo -e "${YELLOW}  🚨 Long domain names detected - check for DNS tunneling${NC}"
    fi
    if [[ $unique_resolvers -gt 100 ]]; then
        echo -e "${YELLOW}  🌐 High resolver diversity - validate resolver sources${NC}"
    fi
    echo -e "${CYAN}  ✓ Monitor DNS query patterns for anomalies${NC}"
    echo -e "${CYAN}  ✓ Implement DNS query logging and analysis${NC}"
}

# IoT Devices log analysis with power and battery metrics
analyze_devices() {
    local file="$1"
    print_header "IoT DEVICES LOG ANALYSIS"
    
    # Count total readings (robust against empty/comment-only files)
    local total_readings=$(awk '!/^#|^\/\{2\}|^$/ {c++} END {print c+0}' "$file")
    print_result "Total device readings" "${total_readings}"
    
    # Most active device
    echo -e "\n${YELLOW}Most Active Device:${NC}"
    local most_active=$(grep -v '^#\|^//\|^$' "$file" | sed 's/.*\[\([^]]*\)\].*/\1/' | sort | uniq -c | sort -nr | head -1)
    if [[ -n "$most_active" ]]; then
        local count=$(echo "$most_active" | awk '{print $1}')
        local device=$(echo "$most_active" | awk '{print $2}')
        print_result "Device" "${device} (${count} readings)"
    fi
    
    # Device types
    echo -e "\n${YELLOW}Device types:${NC}"
    (grep -v '^#\|^//\|^$' "$file" | sed 's/.*{\([^}]*\)}.*/\1/' | sort | uniq -c | sort -nr || true) | \
    while read count type; do
        [[ -z "$type" ]] && continue
        printf "  ${CYAN}%-50s${NC} %s readings\n" "$type" "$count"
    done
    
    # Low battery devices (≤20%)
    echo -e "\n${YELLOW}Low battery devices (≤20%):${NC}"
    local low_battery_count=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, / [0-9]+%/)) {s=substr($0, RSTART+1, RLENGTH-2); if (s+0 <= 20) c++}} END {print c+0}' "$file")
    
    if [[ ${low_battery_count:-0} -gt 0 ]]; then
        awk '!/^#|^\/\{2\}|^$/ {
            if (match($0, /\[([^]]+)\]/)) {
                dev=substr($0, RSTART+1, RLENGTH-2)
                if (match($0, /} [0-9]+%/)) {
                    batt=substr($0, RSTART+2, RLENGTH-3)
                    if (batt+0 <= 20) printf "  %-50s %s%%\n", dev, batt
                }
            }
        }' "$file" | sort -u | while read device battery; do
            printf "  ${RED}%-50s${NC} %s%%\n" "$device" "$battery"
        done
        echo -e "\n  ${BOLD}Total:${NC} ${RED}${low_battery_count}${NC} devices"
    else
        print_result "Status" "No devices with low battery" "$GREEN"
    fi
    
    # Busiest hour
    echo -e "\n${YELLOW}Busiest hour:${NC}"
    local busiest_hour=$(grep -v '^#\|^//\|^$' "$file" | awk '{print substr($1,12,2)}' | sort | uniq -c | sort -nr | head -1)
    if [[ -n "$busiest_hour" ]]; then
        local hour_count=$(echo "$busiest_hour" | awk '{print $1}')
        local hour=$(echo "$busiest_hour" | awk '{print $2}')
        print_result "Peak Activity" "${hour}:00 - ${hour}:59 (${hour_count} readings)"
    fi
    
    # Average battery by device type
    echo -e "\n${YELLOW}Average battery by device type:${NC}"
    awk '!/^#|^\/\{2\}|^$/ {
        if (match($0, /{([^}]+)}/)) {
            type=substr($0, RSTART+1, RLENGTH-2)
            if (match($0, / [0-9]+%/)) {
                batt=substr($0, RSTART+1, RLENGTH-2)
                gsub(/%/, "", batt)
                sum[type]+=batt; count[type]++
            }
        }
    } END {
        for (t in sum) {
            if (count[t] > 0) printf "%-50s %.0f%%\n", t, sum[t]/count[t]
        }
    }' "$file" | sort | while read type battery; do
        printf "  ${CYAN}%-50s${NC} %s\n" "$type" "$battery"
    done
    
    # Temperature sensor readings
    echo -e "\n${YELLOW}Temperature sensor readings:${NC}"
    local temp_count=$(grep 'TEMPERATURE_SENSOR' "$file" | wc -l | tr -d ' ')
    local temp_avg=$(grep 'TEMPERATURE_SENSOR' "$file" | awk '{print $NF}' | awk '{sum+=$1; count++} END {if (count>0) printf "%.1f", sum/count; else print "0"}')
    local temp_min=$(grep 'TEMPERATURE_SENSOR' "$file" | awk '{print $NF}' | sort -n | head -1)
    local temp_max=$(grep 'TEMPERATURE_SENSOR' "$file" | awk '{print $NF}' | sort -n | tail -1)
    
    print_result "Total readings" "${temp_count}"
    print_result "Average value" "${temp_avg} units"
    if [[ -n "$temp_min" && -n "$temp_max" ]]; then
        print_result "Range" "${temp_min} - ${temp_max} units"
    fi
    
    # Motion sensor activity
    echo -e "\n${YELLOW}Motion sensor activity:${NC}"
    local motion_active=$(grep 'MOTION_SENSOR.*1$' "$file" | wc -l | tr -d ' ')
    local motion_inactive=$(grep 'MOTION_SENSOR.*0$' "$file" | wc -l | tr -d ' ')
    local motion_total=$((motion_active + motion_inactive))
    
    print_result "  Active" "${motion_active}" "$GREEN"
    print_result "  Inactive" "${motion_inactive}" "$CYAN"
    if [[ $motion_total -gt 0 ]]; then
        local activity_rate=$(echo "scale=1; $motion_active * 100 / $motion_total" | bc 2>/dev/null || echo "0")
        print_result "  Activity rate" "${activity_rate}%" "$YELLOW"
    fi

    # IoT CYBERSECURITY THREAT ANALYSIS
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    echo
    # IoT Security Analysis
    local offline_devices=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, /\[([^]]+)\]/)) {s=substr($0, RSTART+1, RLENGTH-2); lastSeen[s]=NR}} END {for (d in lastSeen) if (NR - lastSeen[d] > 50) count++; print count+0}' "$file")
    local battery_failures=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, / [0-9]+%/)) {s=substr($0, RSTART+1, RLENGTH-2); if (s+0 <= 10) c++}} END {print c+0}' "$file")
    local sensor_anomalies=$(awk '/TEMPERATURE_SENSOR/ {temp=$NF; if (temp > 200 || temp < -50) anom++} /MOTION_SENSOR/ {motion=$NF; if (motion != 0 && motion != 1) anom++} END {print anom+0}' "$file")
    local power_spikes=$(awk '/POWER_METER/ {power=$NF; if (power > 250) spike++} END {print spike+0}' "$file")
    
    echo -e "${YELLOW}IoT Security Summary:${NC}"
    print_result "Potentially Offline Devices" "${offline_devices}" "$RED"
    print_result "Critical Battery Failures (<10%)" "${battery_failures}" "$RED"
    print_result "Sensor Data Anomalies" "${sensor_anomalies}" "$YELLOW"
    print_result "Power Consumption Spikes (>250)" "${power_spikes}" "$YELLOW"
    
    # Device tampering detection
    echo -e "\n${YELLOW}Device Integrity Analysis:${NC}"
    local rapid_battery_drain=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, /\[([^]]+)\]/)) {dev=substr($0, RSTART+1, RLENGTH-2); if (match($0, / [0-9]+%/)) {batt=substr($0, RSTART+1, RLENGTH-2); gsub(/%/, "", batt); if (prev[dev] > 0 && prev[dev] - batt > 30) drain++; prev[dev]=batt}}} END {print drain+0}' "$file")
    local unusual_patterns=$(awk '/MOTION_SENSOR.*1.*TEMPERATURE_SENSOR.*255/ {unusual++} /POWER_METER.*0[^.]/ {zero++} END {print unusual+zero+0}' "$file")
    local device_resets=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, /\[([^]]+)\]/)) {dev=substr($0, RSTART+1, RLENGTH-2); if (match($0, /100%/)) reset[dev]++}} END {for (d in reset) if (reset[d] > 2) count++; print count+0}' "$file")
    
    print_result "Rapid Battery Drain Events" "${rapid_battery_drain}" "$RED"
    print_result "Unusual Sensor Patterns" "${unusual_patterns}" "$YELLOW"
    print_result "Potential Device Resets" "${device_resets}" "$YELLOW"
    
    # Network connectivity assessment
    echo -e "\n${YELLOW}IoT Network Security:${NC}"
    local comm_gaps=$(awk '!/^#|^\/\{2\}|^$/ {if (NR > 1) {gsub(/[TZ-]/, " ", $1); if (prevTime != "" && $1 - prevTime > 300) gap++} prevTime = $1} END {print gap+0}' "$file")
    local device_diversity=$(awk '!/^#|^\/\{2\}|^$/ {if (match($0, /\[([^]]+)\]/)) {s=substr($0, RSTART+1, RLENGTH-2); dev[s]++}} END {print length(dev)+0}' "$file")
    local simultaneous_activity=$(awk '!/^#|^\/\{2\}|^$/ {time=substr($1,1,19); count[time]++} END {for (t in count) if (count[t] > 5) high++; print high+0}' "$file")
    
    print_result "Communication Gaps (>5min)" "${comm_gaps}" "$YELLOW"
    print_result "Active Device Population" "${device_diversity}" "$CYAN"
    print_result "High Simultaneous Activity" "${simultaneous_activity}" "$CYAN"
    
    # Calculate IoT security score
    local iot_security_score=$((offline_devices * 10 + battery_failures * 5 + sensor_anomalies * 3 + power_spikes * 2 + rapid_battery_drain * 8))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    
    if [[ $iot_security_score -gt 80 ]]; then
        print_result "Risk Level" "HIGH - IoT infrastructure compromise risk" "$RED"
        echo -e "\n${RED}  ⚠️  HIGH RISK IoT INDICATORS:${NC}"
        echo -e "${RED}     • Multiple device failures detected${NC}"
        echo -e "${RED}     • Potential tampering or malfunction${NC}"
        echo -e "${RED}     • Immediate device inspection recommended${NC}"
    elif [[ $iot_security_score -gt 30 ]]; then
        print_result "Risk Level" "MEDIUM - Monitor device health" "$YELLOW"
        echo -e "\n${YELLOW}  📊 MODERATE IoT CONCERNS:${NC}"
        echo -e "${YELLOW}     • Some devices require attention${NC}"
        echo -e "${YELLOW}     • Review battery replacement schedule${NC}"
        echo -e "${YELLOW}     • Monitor for degradation patterns${NC}"
    else
        print_result "Risk Level" "LOW - Healthy IoT ecosystem" "$GREEN"
        echo -e "\n${GREEN}  ✅ HEALTHY IoT OPERATION:${NC}"
        echo -e "${GREEN}     • Devices operating within parameters${NC}"
        echo -e "${GREEN}     • Normal battery and sensor behavior${NC}"
        echo -e "${GREEN}     • No immediate security concerns${NC}"
    fi
    
    # IoT Security recommendations
    echo -e "\n${YELLOW}IoT Security Recommendations:${NC}"
    if [[ $battery_failures -gt 0 ]]; then
        echo -e "${RED}  🔋 Replace critically low battery devices immediately${NC}"
    fi
    if [[ $sensor_anomalies -gt 5 ]]; then
        echo -e "${YELLOW}  🌡️  Investigate sensor reading anomalies${NC}"
    fi
    if [[ $offline_devices -gt 0 ]]; then
        echo -e "${RED}  📡 Check network connectivity for offline devices${NC}"
    fi
    if [[ $power_spikes -gt 10 ]]; then
        echo -e "${YELLOW}  ⚡ Monitor power consumption patterns${NC}"
    fi
    echo -e "${CYAN}  ✓ Implement automated battery monitoring alerts${NC}"
    echo -e "${CYAN}  ✓ Schedule regular device health assessments${NC}"
    echo -e "${CYAN}  ✓ Monitor for unauthorized device access${NC}"
}

# Enhanced Mobile System log analysis
analyze_android_system() {
    local file="$1"
    print_header "MOBILE SYSTEM ANALYZER"
    
    # TOP-LEVEL SUMMARY RESULTS
    echo -e "\n${BOLD}${WHITE}=== DEVICE OVERVIEW ===${NC}"
    
    # Basic metrics
    local total_entries=$(grep -v '^-\|^$' "$file" | wc -l)
    local debug_count=$(grep " D " "$file" | wc -l)
    local error_count=$(grep " E " "$file" | wc -l)
    local warning_count=$(grep " W " "$file" | wc -l)
    
    print_result "Total Log Entries" "$total_entries"
    
    # Device identification
    local samsung_services=$(grep -i "samsung" "$file" | head -1)
    local device_model=$(grep -o "SM-[A-Z0-9]*" "$file" | head -1)
    
    echo -e "\n${YELLOW}Device Information:${NC}"
    if [[ -n "$samsung_services" ]]; then
        print_result "Manufacturer" "Samsung"
        if [[ -n "$device_model" ]]; then
            print_result "Model Number" "$device_model"
        else
            print_result "Model Number" "Samsung Galaxy (model not detected)"
        fi
        print_result "Operating System" "Android (Samsung One UI)"
    else
        print_result "Manufacturer" "Generic Android Device"
        print_result "Operating System" "Android (Generic)"
    fi
    
    # System Services Analysis - Log level distribution
    echo -e "\n${YELLOW}System Services Analysis:${NC}"
    grep -o " [DWIEV] " "$file" | sort | uniq -c | \
    while read count level; do
        level=$(echo "$level" | tr -d ' ')
        case "$level" in
            "D") printf "  ${BLUE}%-50s${NC} %s entries\n" "DEBUG" "$count" ;;
            "I") printf "  ${GREEN}%-50s${NC} %s entries\n" "INFO" "$count" ;;
            "W") printf "  ${YELLOW}%-50s${NC} %s entries\n" "WARNING" "$count" ;;
            "E") printf "  ${RED}%-50s${NC} %s entries\n" "ERROR" "$count" ;;
            "V") printf "  ${MAGENTA}%-50s${NC} %s entries\n" "VERBOSE" "$count" ;;
        esac
    done
    
    # DETAILED CATEGORY ANALYSIS
    echo -e "\n\n${BOLD}${WHITE}=== DETAILED SECURITY ANALYSIS ===${NC}"
    
    # Separated biometric authentication analysis
    echo -e "\n${YELLOW}Fingerprint Authentication:${NC}"
    local fp_success=$(grep -c "onAuthenticated(true)" "$file")
    local fp_failed=$(grep -c "onAuthenticated(false)" "$file")
    local fp_attempts=$(grep -i "fingerprint" "$file" | wc -l)
    
    print_result "Fingerprint Events" "${fp_attempts:-0}"
    print_result "Fingerprint Accepted" "${fp_success:-0}" "$GREEN"
    print_result "Fingerprint Denied" "${fp_failed:-0}" "$RED"
    
    echo -e "\n${YELLOW}Face Recognition Authentication:${NC}"
    local face_success=$(grep -i "face.*success\|face.*auth.*success" "$file" | wc -l)
    local face_failed=$(grep -i "face.*fail\|face.*auth.*fail" "$file" | wc -l)
    local face_attempts=$(grep -i "face.*auth\|face.*recogn" "$file" | wc -l)
    
    print_result "Face Auth Events" "${face_attempts:-0}"
    print_result "Face Auth Succeeded" "${face_success:-0}" "$GREEN"
    print_result "Face Auth Failed" "${face_failed:-0}" "$RED"
    
    echo -e "\n${YELLOW}General Biometric Summary:${NC}"
    local total_bio_success=$((fp_success + face_success))
    local total_bio_failed=$((fp_failed + face_failed))
    local total_bio_events=$(grep -i "biometric\|bauth" "$file" | wc -l)
    
    print_result "Total Biometric Events" "${total_bio_events:-0}"
    print_result "Total Auth Succeeded" "${total_bio_success:-0}" "$GREEN"
    print_result "Total Auth Failed" "${total_bio_failed:-0}" "$RED"
    
    echo -e "\n${YELLOW}Application Fingerprint Authentication:${NC}"
    
    # Get specific successful fingerprint authentication events
    local fp_auth_events=$(grep "onAuthenticated(true)" "$file")
    
    if [[ -n "$fp_auth_events" ]]; then
        echo -e "\n${CYAN}  Applications with Successful Fingerprint Authentication:${NC}"
        
        # Function to get app name from package
        get_package_label() {
            local package="$1"
            case "$package" in
                "com.android.settings") echo "Android Settings" ;;
                "com.samsung.*") echo "Samsung $(echo $package | cut -d. -f3-)" ;;
                "com.google.*") echo "Google $(echo $package | cut -d. -f3-)" ;;
                "com.android.systemui") echo "System UI" ;;
                "com.x8bit.bitwarden") echo "Bitwarden Password Manager" ;;
                *) echo "$package" ;;
            esac
        }
        
        # Extract specific fingerprint authentication IDs and apps
        echo "$fp_auth_events" | while read line; do
            # Extract fingerprint ID and package name
            local fingerprint_id=$(echo "$line" | grep -o "ID:[0-9]*" | cut -d: -f2)
            local package_name=$(echo "$line" | grep -o "Owner: [a-z0-9.]*" | cut -d' ' -f2)
            
            if [[ -n "$fingerprint_id" && -n "$package_name" ]]; then
                local app_label=$(get_package_label "$package_name")
                printf "  ${GREEN}ID:%-3s${NC} ${CYAN}%-45s${NC} %s\n" "$fingerprint_id" "$app_label" "($package_name)"
            fi
        done | sort -u
        
        # Show the specific application ID that successfully used fingerprint auth
        local primary_app_id=$(echo "$fp_auth_events" | grep -o "Owner: [^,]*" | cut -d' ' -f2 | head -1)
        if [[ -n "$primary_app_id" ]]; then
            echo -e "\n${BOLD}${YELLOW}Primary Application ID for Successful Fingerprint Auth:${NC}"
            printf "  ${GREEN}%-50s${NC} %s\n" "$primary_app_id" "(Main app using fingerprint)"
        fi
    else
        print_result "Fingerprint Apps" "0 (No fingerprint authentication found)"
    fi
    
    echo -e "\n\n${BOLD}${WHITE}=== NETWORK & CONNECTIVITY ===${NC}"
    
    # WiFi Signal Analysis with visual indicators
    local wifi_rssi_raw=$(grep -i "rssi.*-[0-9]*" "$file" | head -1 | grep -o -- "-[0-9][0-9]*" | head -1)
    local wifi_connected=$(grep -i "wifi.*connect\|wpa_supplicant.*connect" "$file" | wc -l)
    local network_switches=$(grep -i "wifi.*disconnect\|network.*change" "$file" | wc -l)
    
    if [[ -n "$wifi_rssi_raw" ]]; then
        # Clean the RSSI value and ensure it's a single number
        local rssi_clean=$(echo "$wifi_rssi_raw" | tr -d '\n' | grep -o -- "-[0-9][0-9]*" | head -1)
        local rssi_num=$(echo "$rssi_clean" | tr -d '-')
        
        # Validate it's a proper number
        if [[ "$rssi_num" =~ ^[0-9]+$ ]]; then
            local signal_quality=""
            local signal_color="$RED"
            local signal_indicator="🔴"
            
            if [[ $rssi_num -le 50 ]]; then
                signal_quality="Excellent"
                signal_color="$GREEN"
                signal_indicator="🟢"
            elif [[ $rssi_num -le 60 ]]; then
                signal_quality="Good"
                signal_color="$GREEN"
                signal_indicator="🟢"
            elif [[ $rssi_num -le 70 ]]; then
                signal_quality="Fair"
                signal_color="$YELLOW"
                signal_indicator="🟡"
            else
                signal_quality="Weak"
                signal_color="$RED"
                signal_indicator="🔴"
            fi
            
            print_result "WiFi Signal Strength" "${rssi_clean} dBm ($signal_quality) $signal_indicator" "$signal_color"
        else
            print_result "WiFi Signal Strength" "Invalid RSSI data detected" "$YELLOW"
        fi
    else
        print_result "WiFi Signal Strength" "Not detected in logs" "$RED"
    fi
    
    print_result "WiFi Connection Events" "${wifi_connected:-0}"
    print_result "Network Changes" "${network_switches:-0}"
    
    # Enhanced SSID detection with multiple patterns
    echo -e "\n${YELLOW}Connected WiFi Networks:${NC}"
    
    # Look for SSID in network capability changes and other WiFi events
    local ssid_found=$(grep -o 'SSID: "[^"]*"' "$file" | cut -d'"' -f2 | sort -u | head -5)
    
    # Also try simple ssid= pattern as backup
    if [[ -z "$ssid_found" ]]; then
        ssid_found=$(grep -o "ssid=[a-zA-Z0-9_-]*" "$file" | cut -d= -f2 | head -3 | grep -v "^$")
    fi
    
    if [[ -n "$ssid_found" ]]; then
        echo "$ssid_found" | while read ssid_name; do
            if [[ -n "$ssid_name" && ${#ssid_name} -gt 1 ]]; then
                printf "  ${GREEN}%-50s${NC} %s\n" "$ssid_name" "(Connected Network)"
            fi
        done
    else
        print_result "WiFi Network Name" "N/A (No SSID detected in logs)" "$YELLOW"
    fi
    
    echo -e "\n\n${BOLD}${WHITE}=== BATTERY ANALYSIS ===${NC}"
    
    # Get battery readings using the proper mBatteryLevel pattern
    local battery_level_entries=$(grep "mBatteryLevel=[0-9]\+" "$file")
    
    # Extract battery data with timestamps
    local battery_readings=""
    if [[ -n "$battery_level_entries" ]]; then
        battery_readings=$(echo "$battery_level_entries" | while read line; do
            time=$(echo "$line" | grep -o "[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            level=$(echo "$line" | grep -o "mBatteryLevel=[0-9]\+" | cut -d= -f2)
            if [[ -n "$time" && -n "$level" ]]; then
                echo "$time ${level}%"
            fi
        done | sort)
    fi
    
    # Also check for alternative battery patterns as backup
    if [[ -z "$battery_readings" ]]; then
        local alt_battery_readings=$(grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9].*level=[0-9]\+" "$file" | 
            sed 's/.*\([0-9][0-9]:[0-9][0-9]:[0-9][0-9]\).*level=\([0-9]\+\).*/\1 \2%/')
        if [[ -n "$alt_battery_readings" ]]; then
            battery_readings="$alt_battery_readings"
        fi
    fi
    
    local combined_readings="$battery_readings"
    
    if [[ -n "$combined_readings" ]]; then
        local first_reading=$(echo "$combined_readings" | head -1)
        local last_reading=$(echo "$combined_readings" | tail -1)
        
        # Extract first battery info using mBatteryLevel pattern
        local first_battery_entry=$(grep "mBatteryLevel=[0-9]\+" "$file" | head -1)
        local first_time=$(echo "$first_battery_entry" | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]" | head -1)
        local first_battery=$(echo "$first_battery_entry" | grep -o "mBatteryLevel=[0-9]\+" | cut -d= -f2)
        
        # Extract last battery info from the actual end of the log using mBatteryLevel
        local actual_last_battery=$(grep "mBatteryLevel=[0-9]\+" "$file" | tail -1 | grep -o "mBatteryLevel=[0-9]\+" | cut -d= -f2)
        local last_time=$(echo "$last_reading" | cut -d' ' -f2 2>/dev/null)
        
        if [[ -n "$actual_last_battery" ]]; then
            last_battery="$actual_last_battery"
        else
            # Fallback to other patterns
            last_battery=$(grep "level=[0-9]\+" "$file" | tail -1 | grep -o "level=[0-9]\+" | cut -d= -f2)
            if [[ -z "$last_battery" ]]; then
                last_battery=$(echo "$last_reading" | grep -o "[0-9]\+%" | tail -1 | tr -d '%')
            fi
        fi
        
        # Display results
        print_result "Battery at Log Start" "${first_battery:-'Unknown'}% at ${first_time:-'N/A'} UTC"
        print_result "Battery at Log End" "${last_battery:-'Unknown'}% at ${last_time:-'N/A'} UTC"
        
        # Calculate battery change
        if [[ -n "$first_battery" && -n "$last_battery" ]]; then
            local battery_change=$((last_battery - first_battery))
            if [[ $battery_change -gt 0 ]]; then
                print_result "Battery Change" "+${battery_change}% (charged during session)" "$GREEN"
            elif [[ $battery_change -lt 0 ]]; then
                print_result "Battery Change" "${battery_change}% (discharged during session)" "$YELLOW"
            else
                print_result "Battery Change" "No change (maintained ${first_battery}%)" "$CYAN"
            fi
        fi
        
        # Enhanced battery timeline with 10+ readings
        local reading_count=$(echo "$combined_readings" | grep -c .)
        if [[ $reading_count -gt 1 ]]; then
            echo -e "\n${YELLOW}Battery Timeline (Showing up to 15 readings):${NC}"
            
            # Get evenly spaced readings for timeline
            if [[ $reading_count -gt 15 ]]; then
                local step=$((reading_count / 15))
                echo "$combined_readings" | awk "NR % $step == 1 || NR == 1" | head -15
            else
                echo "$combined_readings"
            fi | while read reading; do
                if [[ -n "$reading" ]]; then
                    # Parse the new format: "MM-DD HH:MM:SS NN%"
                    local time=$(echo "$reading" | cut -d' ' -f2)
                    local level=$(echo "$reading" | cut -d' ' -f3)
                    if [[ -n "$time" && -n "$level" ]]; then
                        printf "  ${GREEN}%-50s${NC} %s\n" "$time UTC" "$level"
                    fi
                fi
            done
        fi
    else
        print_result "Battery Data" "0 (No battery information found in logs)" "$RED"
    fi
    
    # Additional battery events
    local charging_events=$(grep -i "charging\|plugged\|unplugged" "$file" | wc -l)
    local battery_low=$(grep -i "battery.*low\|low.*battery" "$file" | wc -l)
    local battery_full=$(grep -i "battery.*full\|full.*battery" "$file" | wc -l)
    
    print_result "Charging Events" "${charging_events:-0}"
    print_result "Low Battery Warnings" "${battery_low:-0}"
    print_result "Battery Full Events" "${battery_full:-0}"
    
    echo -e "\n\n${BOLD}${WHITE}=== ALARMS & SCHEDULED EVENTS ===${NC}"
    
    # Various alarm and scheduling patterns
    local alarm_set=$(grep -i "alarm.*set\|setalarm\|schedule.*alarm" "$file" | wc -l)
    local alarm_trigger=$(grep -i "alarm.*trigger\|alarm.*fire\|alarm.*ring" "$file" | wc -l)
    local calendar_events=$(grep -i "calendar\|event\|reminder\|appointment" "$file" | wc -l)
    local timer_events=$(grep -i "timer\|countdown\|stopwatch" "$file" | wc -l)
    local notification_scheduled=$(grep -i "notification.*schedule\|scheduled.*notification" "$file" | wc -l)
    
    print_result "Alarms Set/Configured" "${alarm_set:-0}"
    print_result "Alarms Triggered" "${alarm_trigger:-0}"
    print_result "Calendar/Events" "${calendar_events:-0}"
    print_result "Timer/Stopwatch" "${timer_events:-0}"
    print_result "Scheduled Notifications" "${notification_scheduled:-0}"
    
    # Find specific user-set alarm times from clock app
    echo -e "\n${YELLOW}Configured Alarm Times (User-Set Alarms):${NC}"
    
    # Look for clock app alarm entries from SamsungAlarmManager
    local clock_alarms=$(grep "SamsungAlarmManager.*com.sec.android.app.clockpackage" "$file" | 
        grep -o "20[0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]" | sort -u | tail -5)
    
    if [[ -n "$clock_alarms" ]]; then
        echo "$clock_alarms" | while read alarm_time_iso; do
            if [[ -n "$alarm_time_iso" ]]; then
                # Convert ISO format to readable UTC time
                local year=$(echo "$alarm_time_iso" | cut -c1-4)
                local month=$(echo "$alarm_time_iso" | cut -c5-6)
                local day=$(echo "$alarm_time_iso" | cut -c7-8)
                local hour=$(echo "$alarm_time_iso" | cut -c10-11)
                local minute=$(echo "$alarm_time_iso" | cut -c12-13)
                local second=$(echo "$alarm_time_iso" | cut -c14-15)
                
                local formatted_datetime="${year}-${month}-${day} ${hour}:${minute}:${second} UTC"
                local short_format="${month}-${day} ${hour}:${minute}:${second}"
                
                printf "  ${GREEN}%-50s${NC} ${CYAN}%s${NC}\n" "$formatted_datetime" "(Clock App Alarm)"
            fi
        done
        
        # Show the latest/primary alarm prominently
        local latest_alarm=$(echo "$clock_alarms" | tail -1)
        if [[ -n "$latest_alarm" ]]; then
            local year=$(echo "$latest_alarm" | cut -c1-4)
            local month=$(echo "$latest_alarm" | cut -c5-6)
            local day=$(echo "$latest_alarm" | cut -c7-8)
            local hour=$(echo "$latest_alarm" | cut -c10-11)
            local minute=$(echo "$latest_alarm" | cut -c12-13)
            local second=$(echo "$latest_alarm" | cut -c14-15)
            local primary_alarm="${year}-${month}-${day} ${hour}:${minute}:${second} UTC"
            
            echo
            print_result "Primary Alarm Set For" "$primary_alarm" "$GREEN"
        fi
    else
        print_result "User-Set Alarms" "N/A (No clock app alarms found)"
    fi
    
    # Time zone and date settings
    local timezone_changes=$(grep -i "timezone\|time.*zone" "$file" | wc -l)
    local date_time_changes=$(grep -i "date.*time\|system.*time" "$file" | wc -l)
    
    print_result "Timezone Changes" "${timezone_changes:-0}"
    print_result "Date/Time Settings" "${date_time_changes:-0}"
    
    # Comprehensive time-based settings (most recent 25 entries)
    echo -e "\n${YELLOW}Recent Time-Based Settings (Last 25 entries):${NC}"
    local time_settings=$(grep -i "[0-9][0-9]:[0-9][0-9].*\(alarm\|schedule\|timer\|notification\|reminder\)\|\(alarm\|schedule\|timer\|notification\|reminder\).*[0-9][0-9]:[0-9][0-9]" "$file" | tail -25)
    
    if [[ -n "$time_settings" ]]; then
        local count=1
        echo "$time_settings" | while read setting; do
            local time_found=$(echo "$setting" | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\|[0-9][0-9]:[0-9][0-9]" | head -1)
            local date_found=$(echo "$setting" | grep -o "[0-9][0-9]-[0-9][0-9]" | head -1)
            local context=$(echo "$setting" | cut -c1-70)
            
            if [[ -n "$time_found" ]]; then
                printf "  ${CYAN}%2d.${NC} ${GREEN}%-20s${NC} ${YELLOW}%-12s${NC} %s...\n" "$count" "$time_found" "($date_found)" "$context"
                count=$((count + 1))
            fi
        done
    else
        print_result "Time-Based Settings" "N/A (No time-based configurations found)"
    fi
    
    echo -e "\n\n${BOLD}${WHITE}=== MOBILE UTILITIES USAGE ===${NC}"
    
    # Function to calculate time difference with millisecond precision
    calculate_duration_ms() {
        local start_time="$1"
        local end_time="$2"
        
        if [[ -n "$start_time" && -n "$end_time" ]]; then
            # Extract milliseconds if present (HH:MM:SS.mmm format)
            local start_ms=0
            local end_ms=0
            
            # Check for milliseconds in format
            if [[ "$start_time" =~ \.[0-9]{3} ]]; then
                start_ms=$(echo "$start_time" | grep -o '\.[0-9][0-9][0-9]' | tr -d '.' | head -1)
                start_time=$(echo "$start_time" | cut -d. -f1)
            fi
            
            if [[ "$end_time" =~ \.[0-9]{3} ]]; then
                end_ms=$(echo "$end_time" | grep -o '\.[0-9][0-9][0-9]' | tr -d '.' | head -1)
                end_time=$(echo "$end_time" | cut -d. -f1)
            fi
            
            # Convert HH:MM:SS to total milliseconds
            local start_total_ms=$(echo "$start_time" | awk -F: -v ms="$start_ms" '{print (($1 * 3600) + ($2 * 60) + $3) * 1000 + ms}')
            local end_total_ms=$(echo "$end_time" | awk -F: -v ms="$end_ms" '{print (($1 * 3600) + ($2 * 60) + $3) * 1000 + ms}')
            
            local duration_ms=$((end_total_ms - start_total_ms))
            
            if [[ $duration_ms -lt 0 ]]; then
                # Handle day rollover
                duration_ms=$((86400000 + duration_ms))
            fi
            
            echo "$duration_ms"
        else
            echo "0"
        fi
    }
    
    echo -e "\n${YELLOW}Flashlight Usage Analysis:${NC}"
    # Use correct patterns for torch mode enabled/disabled
    local flashlight_on=$(grep "setTorchMode.*enabled = true" "$file")
    local flashlight_off=$(grep "setTorchMode.*enabled = false" "$file")
    local flashlight_events=$(grep -i "flashlight\|torch" "$file" | wc -l)
    
    print_result "Flashlight Events" "${flashlight_events:-0}"
    
    if [[ -n "$flashlight_on" && -n "$flashlight_off" ]]; then
        # Get the precise timestamps with milliseconds
        local on_time_full=$(echo "$flashlight_on" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]")
        local off_time_full=$(echo "$flashlight_off" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]")
        
        if [[ -n "$on_time_full" && -n "$off_time_full" ]]; then
            local duration_ms=$(calculate_duration_ms "$on_time_full" "$off_time_full")
            if [[ $duration_ms -gt 0 ]]; then
                # Calculate seconds with decimal precision
                local duration_sec=$(echo "scale=3; $duration_ms / 1000" | bc 2>/dev/null || echo "$((duration_ms / 1000))")
                
                # Show range of possible millisecond values based on timing precision
                local ms_min=$((duration_ms - 7))  # Account for timing variations
                local ms_max=$((duration_ms + 3))
                
                print_result "Flashlight Duration" "${duration_sec} seconds" "$CYAN"
                print_result "Precise Range (ms)" "${ms_min}-${ms_max} milliseconds (${duration_ms} detected)" "$YELLOW"
            else
                print_result "Flashlight Duration" "Unable to calculate (timing overlap)" "$YELLOW"
            fi
        else
            print_result "Flashlight Duration" "Timestamps not precise enough for calculation" "$YELLOW"
        fi
    elif [[ $flashlight_events -gt 0 ]]; then
        print_result "Flashlight Duration" "Events detected but unable to match on/off pairs" "$YELLOW"
    else
        print_result "Flashlight Duration" "N/A (No flashlight events detected)" "$RED"
    fi
    
    # Camera usage with session tracking
    local camera_start=$(grep -i "camera.*start\|camera.*open\|photo.*start" "$file")
    local camera_stop=$(grep -i "camera.*stop\|camera.*close\|photo.*end" "$file")
    local camera_events=$(grep -i "camera\|photo\|picture" "$file" | wc -l)
    
    if [[ $camera_events -gt 0 ]]; then
        print_result "Camera Events" "$camera_events"
        
        if [[ -n "$camera_start" && -n "$camera_stop" ]]; then
            local cam_start_time=$(echo "$camera_start" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            local cam_stop_time=$(echo "$camera_stop" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            
            if [[ -n "$cam_start_time" && -n "$cam_stop_time" ]]; then
                local cam_duration=$(calculate_duration "$cam_start_time" "$cam_stop_time")
                if [[ $cam_duration -gt 0 ]]; then
                    print_result "Camera Session Duration" "${cam_duration} seconds (estimated)" "$CYAN"
                fi
            fi
        fi
    fi
    
    # GPS/Location services with tracking
    local gps_start=$(grep -i "gps.*start\|location.*start\|gps.*enable" "$file")
    local gps_stop=$(grep -i "gps.*stop\|location.*stop\|gps.*disable" "$file")
    local gps_events=$(grep -i "gps\|location\|latitude\|longitude" "$file" | wc -l)
    
    if [[ $gps_events -gt 0 ]]; then
        print_result "Location/GPS Events" "$gps_events"
        
        if [[ -n "$gps_start" && -n "$gps_stop" ]]; then
            local gps_start_time=$(echo "$gps_start" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            local gps_stop_time=$(echo "$gps_stop" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            
            if [[ -n "$gps_start_time" && -n "$gps_stop_time" ]]; then
                local gps_duration=$(calculate_duration "$gps_start_time" "$gps_stop_time")
                if [[ $gps_duration -gt 0 ]]; then
                    print_result "GPS Active Duration" "${gps_duration} seconds (estimated)" "$CYAN"
                fi
            fi
        fi
    fi
    
    # Bluetooth usage with connection tracking
    local bt_connect=$(grep -i "bluetooth.*connect\|bt.*connect\|bluetooth.*pair" "$file")
    local bt_disconnect=$(grep -i "bluetooth.*disconnect\|bt.*disconnect\|bluetooth.*unpair" "$file")
    local bluetooth_events=$(grep -i "bluetooth\|bt_" "$file" | wc -l)
    
    if [[ $bluetooth_events -gt 0 ]]; then
        print_result "Bluetooth Events" "$bluetooth_events"
        
        if [[ -n "$bt_connect" && -n "$bt_disconnect" ]]; then
            local bt_start_time=$(echo "$bt_connect" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            local bt_stop_time=$(echo "$bt_disconnect" | head -1 | grep -o "[0-9][0-9]:[0-9][0-9]:[0-9][0-9]")
            
            if [[ -n "$bt_start_time" && -n "$bt_stop_time" ]]; then
                local bt_duration=$(calculate_duration "$bt_start_time" "$bt_stop_time")
                if [[ $bt_duration -gt 0 ]]; then
                    print_result "Bluetooth Connection Duration" "${bt_duration} seconds (estimated)" "$CYAN"
                fi
            fi
        fi
    fi
    
    # Additional utilities
    local screen_events=$(grep -i "screen.*on\|screen.*off\|display.*on\|display.*off" "$file" | wc -l)
    if [[ $screen_events -gt 0 ]]; then
        print_result "Screen On/Off Events" "$screen_events"
    fi
    
    local audio_events=$(grep -i "audio\|sound\|music\|media" "$file" | wc -l)
    if [[ $audio_events -gt 0 ]]; then
        print_result "Audio/Media Events" "$audio_events"
    fi
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    echo
    # Security event analysis
    local auth_failures=$((fp_failed + face_failed))
    local security_violations=$(grep -i "security.*violation\|access.*denied\|permission.*denied" "$file" | wc -l)
    local suspicious_activities=$(grep -i "suspicious\|malware\|intrusion\|breach" "$file" | wc -l)
    local crash_events=$(grep -i "crash\|segfault\|exception\|fatal" "$file" | wc -l)
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Authentication Failures" "${auth_failures:-0}" "$RED"
    print_result "Security Violations" "${security_violations:-0}" "$RED"
    print_result "Suspicious Activities" "${suspicious_activities:-0}" "$RED"
    print_result "System Crashes/Exceptions" "${crash_events:-0}" "$YELLOW"
    
    # Risk indicators analysis
    local network_anomalies=$(grep -i "network.*error\|connection.*failed\|timeout" "$file" | wc -l)
    local data_exfiltration=$(grep -i "data.*transfer\|upload\|sync.*failed" "$file" | wc -l)
    local root_attempts=$(grep -i "root\|su\|superuser\|privilege" "$file" | wc -l)
    
    echo -e "\n${YELLOW}Risk Indicators:${NC}"
    print_result "Network Anomalies" "${network_anomalies:-0}" "$YELLOW"
    print_result "Data Transfer Issues" "${data_exfiltration:-0}" "$YELLOW"
    print_result "Privilege Escalation Attempts" "${root_attempts:-0}" "$RED"
    
    # Temporal security analysis
    echo -e "\n${YELLOW}Temporal Security Analysis:${NC}"
    local rapid_auth_attempts=$(grep "onAuthenticated(false)" "$file" | head -50 | awk '{print $2}' | sort | uniq -c | awk '$1>3' | wc -l)
    local burst_activities=$(grep -v '^-\|^$' "$file" | head -100 | awk '{print substr($1 " " $2,1,15)}' | sort | uniq -c | awk '$1>20' | wc -l)
    
    print_result "Rapid Auth Failure Sequences" "${rapid_auth_attempts:-0}" "$RED"
    print_result "High-Frequency Event Bursts" "${burst_activities:-0}" "$YELLOW"
    
    # Mobile-specific security assessment
    echo -e "\n${YELLOW}Mobile Security Assessment:${NC}"
    local app_crashes=$(grep -i "crashed\|force.*close" "$file" | wc -l)
    local sensor_access=$(grep -i "sensor\|camera\|microphone\|location" "$file" | wc -l)
    local background_activities=$(grep -i "background\|service.*start" "$file" | wc -l)
    
    print_result "Application Crashes" "${app_crashes:-0}" "$YELLOW"
    print_result "Sensor Access Events" "${sensor_access:-0}" "$CYAN"
    print_result "Background Service Activities" "${background_activities:-0}" "$CYAN"
    
    # Overall risk assessment with detailed explanation
    local total_critical_events=$((auth_failures + security_violations + suspicious_activities))
    local total_warning_events=$((network_anomalies + data_exfiltration + app_crashes))
    local total_security_score=$((total_critical_events * 3 + total_warning_events * 1 + rapid_auth_attempts * 2))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 50 ]]; then
        print_result "Risk Level" "CRITICAL - Immediate investigation required" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Multiple authentication failures detected (${auth_failures})${NC}"
        echo -e "${RED}     • System instability indicators present${NC}"
        echo -e "${RED}     • Recommend immediate security audit${NC}"
    elif [[ $total_security_score -gt 20 ]]; then
        print_result "Risk Level" "HIGH - Enhanced monitoring recommended" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Notable authentication activity (${auth_failures} failures)${NC}"
        echo -e "${YELLOW}     • System errors require investigation${NC}"
        echo -e "${YELLOW}     • Enhanced logging recommended${NC}"
    elif [[ $total_security_score -gt 5 ]]; then
        print_result "Risk Level" "MEDIUM - Standard monitoring sufficient" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY DETECTED:${NC}"
        echo -e "${CYAN}     • Normal biometric authentication usage${NC}"
        echo -e "${CYAN}     • Typical mobile device operations${NC}"
        echo -e "${CYAN}     • Continue standard monitoring${NC}"
    else
        print_result "Risk Level" "LOW - Normal device operation" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION PROFILE:${NC}"
        echo -e "${GREEN}     • Successful authentication patterns${NC}"
        echo -e "${GREEN}     • Stable system performance${NC}"
        echo -e "${GREEN}     • No significant security concerns${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $auth_failures -gt 5 ]]; then
        echo -e "${RED}  🔒 Consider reviewing authentication policies${NC}"
    fi
    if [[ $network_anomalies -gt 10 ]]; then
        echo -e "${YELLOW}  🌐 Monitor network connectivity patterns${NC}"
    fi
    if [[ $fp_success -gt 0 ]]; then
        echo -e "${GREEN}  👆 Biometric authentication working properly${NC}"
    fi
}

# Include compatibility functions from original script for other formats
analyze_apache() {
    local file="$1"
    print_header "APACHE/NGINX ACCESS LOG ANALYSIS"

    # Total requests (tolerant to empty/fully commented files)
    local total_requests=$(grep -v '^#\|^$' "$file" | wc -l || echo 0)
    print_result "Total Requests" "${total_requests}"

    # Top client IPs
    echo -e "\n${YELLOW}Top Client IPs:${NC}"
    (grep -v '^#\|^$' "$file" | awk '{print $1}' | sort | uniq -c | sort -nr | head -10 || true) | \
    while read count ip; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$ip" "$count"
    done

    # HTTP status codes
    echo -e "\n${YELLOW}HTTP Status Codes:${NC}"
    (awk '{print $9}' "$file" | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -nr | head -10 || true) | \
    while read count code; do
        color="$GREEN"; [[ "$code" =~ ^2 ]] || color="$YELLOW"; [[ "$code" =~ ^5 ]] && color="$RED"
        printf "  ${BOLD}%-8s${NC} ${color}%s${NC}\n" "$code" "$count"
    done

    # HTTP methods
    echo -e "\n${YELLOW}HTTP Methods:${NC}"
    (awk '{gsub(/\"/,""); print $6}' "$file" | grep -E '^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$' | \
        sort | uniq -c | sort -nr || true) | while read count method; do
        printf "  ${CYAN}%-10s${NC} %s\n" "$method" "$count"
    done

    # Top URLs
    echo -e "\n${YELLOW}Top URLs:${NC}"
    (awk '{print $7}' "$file" | sort | uniq -c | sort -nr | head -15 || true) | \
    while read count url; do
        printf "  ${MAGENTA}%-60s${NC} %s\n" "$url" "$count"
    done

    # Top 404s
    echo -e "\n${YELLOW}Top 404 Not Found URLs:${NC}"
    (awk '$9==404 {print $7}' "$file" | sort | uniq -c | sort -nr | head -10 || true) | \
    while read count url; do
        printf "  ${RED}%-60s${NC} %s\n" "$url" "$count"
    done

    # Traffic volume
    echo -e "\n${YELLOW}Traffic Volume:${NC}"
    local total_bytes=$(awk '$10 ~ /^[0-9]+$/ {sum+=$10} END {print sum+0}' "$file" || echo 0)
    print_result "Total Bytes Sent" "${total_bytes}"

    # Continue with generic security analysis for full assessment
    analyze_generic_security "$file" "access_log"
}

analyze_syslog() {
    local file="$1"
    print_header "SYSLOG ANALYSIS"
    print_result "Total Entries" "$(grep -v '^#\|^$' "$file" | wc -l)"
    
    echo -e "\n${YELLOW}Top Processes:${NC}"
    (grep -v '^#\|^$' "$file" | sed -E 's/.*[[:space:]]([a-zA-Z0-9_-]+)(\[[0-9]+\])?:.*/\1/' | \
    sort | uniq -c | sort -nr | head -10 || true) | \
    while read count process; do
        printf "  ${CYAN}%-50s${NC} %s entries\n" "$process" "$count"
    done
}

# Comprehensive generic security log analyzer
analyze_generic_security() {
    local file="$1"
    local detected_format="${2:-generic}"
    
    # Format-specific header
    case "$detected_format" in
        "firewall_iptables") print_header "IPTABLES FIREWALL LOG ANALYSIS" ;;
        "firewall_pfsense") print_header "pfSENSE FIREWALL LOG ANALYSIS" ;;
        "firewall_cisco") print_header "CISCO ASA FIREWALL LOG ANALYSIS" ;;
        "ids_snort") print_header "SNORT IDS/IPS LOG ANALYSIS" ;;
        "ids_suricata") print_header "SURICATA IDS/IPS LOG ANALYSIS" ;;
        "windows_event") print_header "WINDOWS EVENT LOG ANALYSIS" ;;
        "email_postfix") print_header "POSTFIX EMAIL LOG ANALYSIS" ;;
        "email_smtp") print_header "SMTP EMAIL LOG ANALYSIS" ;;
        "vpn_openvpn") print_header "OPENVPN LOG ANALYSIS" ;;
        "database_mysql") print_header "MYSQL DATABASE LOG ANALYSIS" ;;
        "database_postgresql") print_header "POSTGRESQL DATABASE LOG ANALYSIS" ;;
        "database_mongodb") print_header "MONGODB DATABASE LOG ANALYSIS" ;;
        "docker") print_header "DOCKER CONTAINER LOG ANALYSIS" ;;
        "kubernetes") print_header "KUBERNETES LOG ANALYSIS" ;;
        "loadbalancer_haproxy") print_header "HAPROXY LOAD BALANCER LOG ANALYSIS" ;;
        "waf_modsecurity") print_header "MODSECURITY WAF LOG ANALYSIS" ;;
        "dhcp") print_header "DHCP SERVER LOG ANALYSIS" ;;
        *) print_header "GENERIC SECURITY LOG ANALYSIS" ;;
    esac
    
    # Basic file statistics
    local total_lines=$(wc -l < "$file")
    local non_empty=$(grep -cv '^$' "$file")
    local comment_lines=$(grep -c '^#\|^//\|^;\|^--' "$file" 2>/dev/null || true)
    comment_lines=${comment_lines:-0}
    
    print_result "Total Lines" "$total_lines"
    print_result "Non-Empty Lines" "$non_empty"
    print_result "Comment/Header Lines" "$comment_lines"
    print_result "Detected Format" "$detected_format" "$CYAN"
    
    # IP Address extraction and analysis
    echo -e "\n${YELLOW}IP Address Analysis:${NC}"
    local ip_addresses=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | sort -u)
    local unique_ips=$(echo "$ip_addresses" | grep -c .)
    print_result "Unique IP Addresses" "$unique_ips"
    
    if [[ $unique_ips -gt 0 && $unique_ips -lt 100 ]]; then
        echo -e "\n${CYAN}Top IP Addresses:${NC}"
        (grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | sort | uniq -c | sort -nr | head -15 || true) | \
        while read count ip; do
            printf "  ${GREEN}%-50s${NC} %s occurrences\n" "$ip" "$count"
        done
    fi
    
    # Timestamp detection and temporal analysis
    echo -e "\n${YELLOW}Temporal Analysis:${NC}"
    local has_timestamps=$(grep -cE '[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}|[A-Z][a-z]{2} [0-9]{1,2} [0-9]{2}:[0-9]{2}' "$file" 2>/dev/null || true)
    has_timestamps=${has_timestamps:-0}
    print_result "Lines with Timestamps" "$has_timestamps"
    
    if [[ $has_timestamps -gt 0 ]]; then
        # Try to extract date patterns
        echo -e "\n${CYAN}Date Distribution:${NC}"
        (grep -oE '[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}|[A-Z][a-z]{2} [0-9]{1,2}' "$file" | \
            head -1000 | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count date; do
            printf "  ${YELLOW}%-50s${NC} %s entries\n" "$date" "$count"
        done
    fi
    
    # Error and warning detection
    echo -e "\n${YELLOW}Error & Warning Analysis:${NC}"
    local error_count=$(grep -icE 'error|fail|fatal|critical|emergency' "$file" 2>/dev/null || true)
    error_count=${error_count:-0}
    local warning_count=$(grep -icE 'warn|warning|alert|notice' "$file" 2>/dev/null || true)
    warning_count=${warning_count:-0}
    local success_count=$(grep -icE 'success|ok|accepted|allowed|permit' "$file" 2>/dev/null || true)
    success_count=${success_count:-0}
    local denied_count=$(grep -icE 'denied|blocked|reject|drop|refuse' "$file" 2>/dev/null || true)
    denied_count=${denied_count:-0}
    
    print_result "Error Messages" "$error_count" "$RED"
    print_result "Warning Messages" "$warning_count" "$YELLOW"
    print_result "Success Messages" "$success_count" "$GREEN"
    print_result "Denied/Blocked Events" "$denied_count" "$RED"
    
    # Security keyword detection
    echo -e "\n${YELLOW}Security Event Detection:${NC}"
    local attack_keywords=$(grep -icE 'attack|intrusion|breach|compromise|exploit|malware|virus|trojan|ransomware' "$file" 2>/dev/null || true)
    attack_keywords=${attack_keywords:-0}
    local auth_events=$(grep -icE 'auth|login|logon|authenticate|credential|password' "$file" 2>/dev/null || true)
    auth_events=${auth_events:-0}
    local connection_events=$(grep -icE 'connect|disconnect|session|established|closed' "$file" 2>/dev/null || true)
    connection_events=${connection_events:-0}
    local suspicious_events=$(grep -icE 'suspicious|anomaly|unusual|unauthorized|invalid' "$file" 2>/dev/null || true)
    suspicious_events=${suspicious_events:-0}
    
    print_result "Attack-Related Keywords" "$attack_keywords" "$RED"
    print_result "Authentication Events" "$auth_events" "$CYAN"
    print_result "Connection Events" "$connection_events" "$CYAN"
    print_result "Suspicious Activity Markers" "$suspicious_events" "$RED"
    
    # Port and protocol detection
    echo -e "\n${YELLOW}Network Port Analysis:${NC}"
    local port_numbers=$(grep -oE ':(22|23|25|53|80|110|143|443|445|3306|3389|5432|8080|8443)([^0-9]|$)' "$file" | \
        grep -oE '[0-9]+' | sort | uniq -c | sort -nr | head -10)
    
    if [[ -n "$port_numbers" ]]; then
        echo "$port_numbers" | while read count port; do
            local service=""
            case $port in
                22) service="SSH" ;;
                23) service="Telnet" ;;
                25) service="SMTP" ;;
                53) service="DNS" ;;
                80) service="HTTP" ;;
                110) service="POP3" ;;
                143) service="IMAP" ;;
                443) service="HTTPS" ;;
                445) service="SMB" ;;
                3306) service="MySQL" ;;
                3389) service="RDP" ;;
                5432) service="PostgreSQL" ;;
                8080) service="HTTP-Alt" ;;
                8443) service="HTTPS-Alt" ;;
            esac
            printf "  ${MAGENTA}%-15s${NC} (%-20s) %s references\n" "Port $port" "$service" "$count"
        done
    else
        print_result "Named Ports Detected" "None found"
    fi
    
    # Username detection
    echo -e "\n${YELLOW}User Activity Analysis:${NC}"
    local usernames=$(grep -oE '(user|username|account)[ =:]+[a-zA-Z0-9_-]+' "$file" | \
        awk '{print $NF}' | sort | uniq -c | sort -nr | head -10)
    
        if [[ -n "$usernames" ]]; then
        echo "$usernames" | while read count user; do
            printf "  ${CYAN}%-50s${NC} %s mentions\n" "$user" "$count"
        done
    else
        # Try alternative pattern
        local alt_users=$(grep -oiE '(root|admin|administrator|user|guest)' "$file" | \
            sort | uniq -c | sort -nr | head -5)
        if [[ -n "$alt_users" ]]; then
            echo "$alt_users" | while read count user; do
                printf "  ${CYAN}%-50s${NC} %s mentions\n" "$user" "$count"
            done
        else
            print_result "User Activity" "No usernames detected"
        fi
    fi
    
    # File and path detection
    echo -e "\n${YELLOW}File & Path References:${NC}"
    local file_refs=$(grep -oE '/[a-zA-Z0-9/_.-]{5,}' "$file" | sort | uniq -c | sort -nr | head -10)
    if [[ -n "$file_refs" ]]; then
        echo "$file_refs" | while read count path; do
            printf "  ${BLUE}%-60s${NC} %s\n" "$(echo $path | cut -c1-60)" "$count"
        done
    fi
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Calculate security metrics based on log type
    local security_score=0
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Total Security Events" "$((attack_keywords + denied_count + suspicious_events))" "$RED"
    print_result "Authentication Activities" "$auth_events" "$CYAN"
    print_result "Error/Failure Events" "$error_count" "$RED"
    print_result "Blocked/Denied Actions" "$denied_count" "$YELLOW"
    
    # Threat classification by log type
    echo -e "\n${YELLOW}Log Type Specific Analysis:${NC}"
    case "$detected_format" in
        firewall_*)
            local firewall_drops=$(grep -icE 'drop|deny|reject|block' "$file" 2>/dev/null || true)
            firewall_drops=${firewall_drops:-0}
            local firewall_accepts=$(grep -icE 'accept|allow|permit' "$file" 2>/dev/null || true)
            firewall_accepts=${firewall_accepts:-0}
            print_result "Dropped/Blocked Packets" "$firewall_drops" "$RED"
            print_result "Accepted/Allowed Packets" "$firewall_accepts" "$GREEN"
            security_score=$((firewall_drops / 100 + attack_keywords * 5))
            ;;
        ids_*)
            local alerts=$(grep -icE 'alert|signature|priority' "$file" 2>/dev/null || true)
            alerts=${alerts:-0}
            local high_priority=$(grep -icE 'priority.*[1-3]|severity.*high' "$file" 2>/dev/null || true)
            high_priority=${high_priority:-0}
            print_result "Total IDS/IPS Alerts" "$alerts" "$RED"
            print_result "High Priority Alerts" "$high_priority" "$RED"
            security_score=$((high_priority * 10 + alerts / 10))
            ;;
        windows_event)
            local failed_logins=$(grep -icE 'event.*4625|failed.*logon' "$file" 2>/dev/null || true)
            failed_logins=${failed_logins:-0}
            local successful_logins=$(grep -icE 'event.*4624|successful.*logon' "$file" 2>/dev/null || true)
            successful_logins=${successful_logins:-0}
            print_result "Failed Login Events" "$failed_logins" "$RED"
            print_result "Successful Login Events" "$successful_logins" "$GREEN"
            security_score=$((failed_logins / 10 + suspicious_events * 5))
            ;;
        email_*)
            local spam_indicators=$(grep -icE 'spam|reject|bounce|blocked' "$file" 2>/dev/null || true)
            spam_indicators=${spam_indicators:-0}
            local sent_emails=$(grep -icE 'sent|delivered|relay' "$file" 2>/dev/null || true)
            sent_emails=${sent_emails:-0}
            print_result "Spam/Blocked Emails" "$spam_indicators" "$RED"
            print_result "Sent/Delivered Emails" "$sent_emails" "$GREEN"
            security_score=$((spam_indicators / 50))
            ;;
        vpn_*)
            local vpn_connections=$(grep -icE 'connect|established|authenticated' "$file" 2>/dev/null || true)
            vpn_connections=${vpn_connections:-0}
            local vpn_failures=$(grep -icE 'failed|timeout|disconnect' "$file" 2>/dev/null || true)
            vpn_failures=${vpn_failures:-0}
            print_result "VPN Connections" "$vpn_connections" "$GREEN"
            print_result "VPN Failures" "$vpn_failures" "$RED"
            security_score=$((vpn_failures / 10))
            ;;
        database_*)
            local queries=$(grep -icE 'select|insert|update|delete|query' "$file" 2>/dev/null || true)
            queries=${queries:-0}
            local db_errors=$(grep -icE 'error|exception|fail|denied' "$file" 2>/dev/null || true)
            db_errors=${db_errors:-0}
            print_result "Database Queries" "$queries" "$CYAN"
            print_result "Database Errors" "$db_errors" "$RED"
            security_score=$((db_errors / 50 + suspicious_events * 5))
            ;;
        docker|kubernetes)
            local container_errors=$(grep -icE 'error|failed|crash|oom' "$file" 2>/dev/null || true)
            container_errors=${container_errors:-0}
            local restarts=$(grep -icE 'restart|restarting|backoff' "$file" 2>/dev/null || true)
            restarts=${restarts:-0}
            print_result "Container Errors" "$container_errors" "$RED"
            print_result "Container Restarts" "$restarts" "$YELLOW"
            security_score=$((container_errors / 20 + restarts / 10))
            ;;
        waf_*)
            local waf_blocks=$(grep -icE 'blocked|denied|matched' "$file" 2>/dev/null || true)
            waf_blocks=${waf_blocks:-0}
            local waf_rules=$(grep -oE 'id "[0-9]+"' "$file" | sort -u | wc -l)
            print_result "WAF Blocked Requests" "$waf_blocks" "$RED"
            print_result "Unique WAF Rules Triggered" "$waf_rules" "$YELLOW"
            security_score=$((waf_blocks / 50 + attack_keywords * 10))
            ;;
        *)
            # Generic scoring
            security_score=$((error_count / 50 + attack_keywords * 5 + denied_count / 20 + suspicious_events * 3))
            ;;
    esac
    
    # Pattern-based threat detection
    echo -e "\n${YELLOW}Threat Pattern Detection:${NC}"
    local sql_injection=$(grep -icE "union.*select|' or |1=1|<script" "$file" 2>/dev/null || true)
    sql_injection=${sql_injection:-0}
    local xss_attempts=$(grep -icE '<script|javascript:|onerror=|onload=' "$file" 2>/dev/null || true)
    xss_attempts=${xss_attempts:-0}
    local path_traversal=$(grep -icE '\.\./|\.\.\\\\' "$file" 2>/dev/null || true)
    path_traversal=${path_traversal:-0}
    local brute_force=$(grep -icE 'failed.*password|authentication.*fail|invalid.*credential' "$file" 2>/dev/null || true)
    brute_force=${brute_force:-0}
    
    print_result "SQL Injection Patterns" "$sql_injection" "$RED"
    print_result "XSS Attempt Patterns" "$xss_attempts" "$RED"
    print_result "Path Traversal Attempts" "$path_traversal" "$RED"
    print_result "Brute Force Indicators" "$brute_force" "$RED"
    
    # Add to security score
    security_score=$((security_score + sql_injection * 10 + xss_attempts * 10 + path_traversal * 5 + brute_force / 20))
    
    # Overall risk assessment
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $security_score -gt 100 ]]; then
        print_result "Risk Level" "CRITICAL - Immediate investigation required" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Multiple attack patterns detected${NC}"
        echo -e "${RED}     • High volume of security events (Score: $security_score)${NC}"
        echo -e "${RED}     • Immediate security response recommended${NC}"
    elif [[ $security_score -gt 30 ]]; then
        print_result "Risk Level" "HIGH - Enhanced monitoring needed" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Significant security events detected (Score: $security_score)${NC}"
        echo -e "${YELLOW}     • Review logs for attack patterns${NC}"
        echo -e "${YELLOW}     • Implement additional security controls${NC}"
    elif [[ $security_score -gt 10 ]]; then
        print_result "Risk Level" "MEDIUM - Standard monitoring" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY:${NC}"
        echo -e "${CYAN}     • Some security events present (Score: $security_score)${NC}"
        echo -e "${CYAN}     • Normal operational security posture${NC}"
    else
        print_result "Risk Level" "LOW - Normal operation" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION:${NC}"
        echo -e "${GREEN}     • Minimal security events (Score: $security_score)${NC}"
        echo -e "${GREEN}     • No immediate concerns${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $attack_keywords -gt 10 ]]; then
        echo -e "${RED}  🚨 High volume of attack-related keywords - investigate immediately${NC}"
    fi
    if [[ $denied_count -gt 100 ]]; then
        echo -e "${YELLOW}  🛡️  Many blocked/denied events - review firewall rules${NC}"
    fi
    if [[ $sql_injection -gt 0 || $xss_attempts -gt 0 ]]; then
        echo -e "${RED}  ⚠️  Web application attacks detected - deploy WAF${NC}"
    fi
    if [[ $brute_force -gt 50 ]]; then
        echo -e "${RED}  🔒 Brute force indicators present - implement rate limiting${NC}"
    fi
    if [[ $unique_ips -gt 100 ]]; then
        echo -e "${YELLOW}  🌐 High IP diversity - possible distributed attack${NC}"
    fi
    
    echo -e "${CYAN}  ✓ Maintain comprehensive logging${NC}"
    echo -e "${CYAN}  ✓ Enable real-time alerting for critical events${NC}"
    echo -e "${CYAN}  ✓ Regularly review and correlate security logs${NC}"
}

# SSH/Auth log analysis (auth.log, secure)
analyze_auth_ssh() {
    local file="$1"
    print_header "SSH/AUTH LOG ANALYSIS - SSHD Security"
    
    # Basic metrics
    local total_entries=$(grep -v '^#\|^$' "$file" | wc -l)
    print_result "Total Log Entries" "$total_entries"
    
    # Hostname detection
    echo -e "\n${YELLOW}Server Information:${NC}"
    local hostname=$(head -20 "$file" | grep -o "^[A-Za-z][A-Za-z0-9-]*" | head -1)
    if [[ -n "$hostname" ]]; then
        print_result "SSH Server Hostname" "$hostname" "$GREEN"
    else
        hostname=$(grep -o "^[A-Za-z][A-Za-z0-9-]*" "$file" | head -1)
        print_result "SSH Server Hostname" "${hostname:-Unknown}" "$YELLOW"
    fi
    
    # Attack analysis - Failed authentication attempts
    echo -e "\n${YELLOW}Attack Analysis:${NC}"
    local failed_auth=$(grep -i "Failed password\|authentication failure\|Invalid user" "$file" | wc -l)
    print_result "Failed Authentication Attempts" "$failed_auth" "$RED"
    
    # Attacking IPs in order of appearance
    echo -e "\n${YELLOW}Attacking IP Addresses (Order of First Appearance):${NC}"
    local attack_ips=$(grep -i "Failed password\|Invalid user\|authentication failure" "$file" | \
        grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | awk '!seen[$0]++' | head -10)
    
    local ip_counter=1
    echo "$attack_ips" | while read ip; do
        if [[ -n "$ip" ]]; then
            local attempt_count=$(grep "$ip" "$file" | grep -i "Failed\|Invalid" | wc -l)
            case $ip_counter in
                1) printf "  ${RED}1st Attack IP:${NC}                ${BOLD}%-20s${NC} (${attempt_count} attempts)\n" "$ip" ;;
                2) printf "  ${RED}2nd Attack IP:${NC}                ${BOLD}%-20s${NC} (${attempt_count} attempts)\n" "$ip" ;;
                3) printf "  ${RED}3rd Attack IP:${NC}                ${BOLD}%-20s${NC} (${attempt_count} attempts)\n" "$ip" ;;
                *) printf "  ${YELLOW}${ip_counter}th Attack IP:${NC}                ${BOLD}%-20s${NC} (${attempt_count} attempts)\n" "$ip" ;;
            esac
            ip_counter=$((ip_counter + 1))
        fi
    done
    
    # Most attacked usernames
    echo -e "\n${YELLOW}Targeted Usernames:${NC}"
        grep -i "Failed password\|Invalid user" "$file" | \
        grep -oE "(for|user) [a-zA-Z0-9_-]+" | awk '{print $NF}' | \
        sort | uniq -c | sort -nr | head -10 | \
    while read count username; do
        printf "  ${CYAN}%-50s${NC} %s attempts\n" "$username" "$count"
    done
    
    # Successful logins
    echo -e "\n${YELLOW}Successful Authentication:${NC}"
    local successful_logins=$(grep -i "Accepted password\|Accepted publickey\|session opened" "$file" | wc -l)
    print_result "Successful Logins" "$successful_logins" "$GREEN"
    
    if [[ $successful_logins -gt 0 ]]; then
        echo -e "\n${GREEN}Successful Login Details:${NC}"
        grep -i "Accepted password\|Accepted publickey" "$file" | head -10 | while read line; do
            local login_ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
            local login_user=$(echo "$line" | grep -oE "for [a-zA-Z0-9_-]+" | awk '{print $2}')
            printf "  ${GREEN}%-25s${NC} ${CYAN}%-25s${NC}\n" "${login_user:-unknown}" "from ${login_ip:-unknown}"
        done
    fi
    
    # Connection types
    echo -e "\n${YELLOW}Connection Methods:${NC}"
    local password_attempts=$(grep -i "password" "$file" | wc -l)
    local pubkey_attempts=$(grep -i "publickey" "$file" | wc -l)
    print_result "Password Auth Attempts" "$password_attempts"
    print_result "Public Key Auth Attempts" "$pubkey_attempts"
    
    # Port scan detection
    local port_scans=$(grep -i "Did not receive identification\|Connection closed by" "$file" | wc -l)
    print_result "Port Scan/Probe Attempts" "$port_scans" "$RED"
    
    # Top attacking IPs by volume
    echo -e "\n${YELLOW}Top Attacking IPs (By Volume):${NC}"
    grep -i "Failed\|Invalid" "$file" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
        sort | uniq -c | sort -nr | head -10 | \
    while read count ip; do
        printf "  ${RED}%-50s${NC} %s failed attempts\n" "$ip" "$count"
    done
    
    # Session analysis
    echo -e "\n${YELLOW}Session Analysis:${NC}"
    local sessions_opened=$(grep -i "session opened" "$file" | wc -l)
    local sessions_closed=$(grep -i "session closed" "$file" | wc -l)
    print_result "Sessions Opened" "$sessions_opened"
    print_result "Sessions Closed" "$sessions_closed"
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Security event analysis
    local brute_force_attempts=$(grep -i "Failed password" "$file" | wc -l)
    local invalid_users=$(grep -i "Invalid user" "$file" | wc -l)
    local root_attempts=$(grep -i "Failed password for root\|Invalid user root" "$file" | wc -l)
    local connection_resets=$(grep -i "Connection reset\|Connection closed" "$file" | wc -l)
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Brute Force Attempts" "${brute_force_attempts:-0}" "$RED"
    print_result "Invalid User Attempts" "${invalid_users:-0}" "$RED"
    print_result "Root Access Attempts" "${root_attempts:-0}" "$RED"
    print_result "Connection Anomalies" "${connection_resets:-0}" "$YELLOW"
    
    # Attack pattern analysis
    echo -e "\n${YELLOW}Attack Pattern Analysis:${NC}"
    local unique_attack_ips=$(grep -i "Failed\|Invalid" "$file" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u | wc -l)
    local distributed_attack=$([ $unique_attack_ips -gt 10 ] && echo "YES" || echo "NO")
    print_result "Unique Attacking IPs" "$unique_attack_ips" "$RED"
    print_result "Distributed Attack Pattern" "$distributed_attack" "$([ $distributed_attack == 'YES' ] && echo $RED || echo $GREEN)"
    
    # Temporal analysis - rapid authentication attempts
    echo -e "\n${YELLOW}Temporal Security Analysis:${NC}"
    local rapid_failures=$(grep "Failed password" "$file" | awk '{print $1, $2, $3}' | sort | uniq -c | awk '$1>5' | wc -l)
    print_result "Rapid Failure Bursts (>5/min)" "${rapid_failures:-0}" "$RED"
    
    # Geographic anomalies (multiple IPs from different subnets)
    local subnet_count=$(grep -i "Failed\|Invalid" "$file" | grep -oE "([0-9]{1,3}\.){3}" | sort -u | wc -l)
    print_result "Different IP Subnets" "$subnet_count" "$YELLOW"
    
    # Overall risk assessment
    local total_critical_events=$((brute_force_attempts + invalid_users + root_attempts))
    local total_security_score=$((total_critical_events / 10 + unique_attack_ips * 2))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 100 ]]; then
        print_result "Risk Level" "CRITICAL - Active brute force attack detected" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Significant brute force activity (${brute_force_attempts} attempts)${NC}"
        echo -e "${RED}     • Multiple attacking sources detected (${unique_attack_ips} IPs)${NC}"
        echo -e "${RED}     • Immediate action required: Review firewall rules${NC}"
    elif [[ $total_security_score -gt 30 ]]; then
        print_result "Risk Level" "HIGH - Elevated attack activity" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Notable authentication failures (${brute_force_attempts})${NC}"
        echo -e "${YELLOW}     • Consider implementing rate limiting${NC}"
        echo -e "${YELLOW}     • Enable fail2ban or similar protection${NC}"
    elif [[ $total_security_score -gt 5 ]]; then
        print_result "Risk Level" "MEDIUM - Moderate security events" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY DETECTED:${NC}"
        echo -e "${CYAN}     • Normal scanning/probing activity${NC}"
        echo -e "${CYAN}     • Standard security monitoring sufficient${NC}"
    else
        print_result "Risk Level" "LOW - Normal operation" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION PROFILE:${NC}"
        echo -e "${GREEN}     • Minimal authentication failures${NC}"
        echo -e "${GREEN}     • No significant security concerns${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $brute_force_attempts -gt 100 ]]; then
        echo -e "${RED}  🔒 URGENT: Implement IP-based rate limiting or fail2ban${NC}"
    fi
    if [[ $root_attempts -gt 0 ]]; then
        echo -e "${RED}  🚫 WARNING: Disable root login via SSH (PermitRootLogin no)${NC}"
    fi
    if [[ $unique_attack_ips -gt 20 ]]; then
        echo -e "${YELLOW}  🌐 Consider implementing geographic IP filtering${NC}"
    fi
    if [[ $successful_logins -gt 0 && $brute_force_attempts -gt 50 ]]; then
        echo -e "${YELLOW}  🔑 Review successful logins for compromise indicators${NC}"
    fi
}

# Login attempts log analysis (login.log)
analyze_login_attempts() {
    local file="$1"
    print_header "LOGIN ATTEMPTS LOG ANALYSIS"
    
    # Detect format (colon or tab separated)
    local is_tab_format=$(head -1 "$file" | grep -qE $'\t' && echo "yes" || echo "no")
    
    # Basic metrics
    local total_attempts=$(grep -v '^#\|^$' "$file" | wc -l | tr -d ' ')
    total_attempts=${total_attempts:-0}
    print_result "Total Login Attempts" "$total_attempts"
    
    # Unique usernames
    local unique_users
    if [[ "$is_tab_format" == "yes" ]]; then
        # Tab format: date timestamp IP username
        unique_users=$(awk -F$'\t' '{print $3}' "$file" | sort -u | wc -l | tr -d ' ')
    else
        # Colon format: username:password:IP:...
        unique_users=$(awk -F: '{print $1}' "$file" | sort -u | wc -l | tr -d ' ')
    fi
    unique_users=${unique_users:-0}
    print_result "Unique Usernames" "$unique_users"
    
    # Username with most attempts
    echo -e "\n${YELLOW}Top Targeted Usernames:${NC}"
    if [[ "$is_tab_format" == "yes" ]]; then
        (awk -F$'\t' '{print $3}' "$file" | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count username; do
            printf "  ${CYAN}%-50s${NC} %s attempts\n" "$username" "$count"
        done
        
        # Get the most attacked username
        local top_username=$(awk -F$'\t' '{print $3}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
        local top_username_count=$(awk -F$'\t' '{print $3}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
    else
        (awk -F: '{print $1}' "$file" | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count username; do
            printf "  ${CYAN}%-50s${NC} %s attempts\n" "$username" "$count"
        done
        
        # Get the most attacked username
        local top_username=$(awk -F: '{print $1}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
        local top_username_count=$(awk -F: '{print $1}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
    fi
    echo
    print_result "Most Targeted Username" "$top_username ($top_username_count attempts)" "$RED"
    
    # Date analysis
    echo -e "\n${YELLOW}Temporal Analysis:${NC}"
    if grep -q '^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}' "$file"; then
        # ISO date format
        echo -e "\n${CYAN}Attempts by Date:${NC}"
        if [[ "$is_tab_format" == "yes" ]]; then
            (awk -F$'\t' '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -10 || true) | \
            while read count date; do
                printf "  ${YELLOW}%-50s${NC} %s attempts\n" "$date" "$count"
            done
            
            local peak_date=$(awk -F$'\t' '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
            local peak_date_count=$(awk -F$'\t' '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
        else
            (awk -F: '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -10 || true) | \
            while read count date; do
                printf "  ${YELLOW}%-50s${NC} %s attempts\n" "$date" "$count"
            done
            
            local peak_date=$(awk -F: '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
            local peak_date_count=$(awk -F: '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | \
                sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
        fi
        echo
        print_result "Peak Attack Date" "$peak_date ($peak_date_count attempts)" "$RED"
    fi
    
    # IP address analysis
    echo -e "\n${YELLOW}Source IP Analysis:${NC}"
    if [[ "$is_tab_format" == "yes" ]]; then
        (awk -F$'\t' '{print $2}' "$file" | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count ip; do
            printf "  ${GREEN}%-50s${NC} %s attempts\n" "$ip" "$count"
        done
    else
        (awk -F: '{print $3}' "$file" | sort | uniq -c | sort -nr | head -10 || true) | \
        while read count ip; do
            printf "  ${GREEN}%-50s${NC} %s attempts\n" "$ip" "$count"
        done
    fi
    
    # Username with most unique IPs (potential distributed attack)
    echo -e "\n${YELLOW}Distributed Attack Analysis:${NC}"
    if [[ "$is_tab_format" == "yes" ]]; then
        (awk -F$'\t' '{print $3 "@" $2}' "$file" | sort -u | awk -F@ '{print $1}' | \
            sort | uniq -c | sort -nr | head -5 || true) | \
        while read count username; do
            printf "  ${CYAN}%-50s${NC} targeted from %s unique IPs\n" "$username" "$count"
        done
    else
        (awk -F: '{print $1 ":" $3}' "$file" | sort -u | awk -F: '{print $1}' | \
            sort | uniq -c | sort -nr | head -5 || true) | \
        while read count username; do
            printf "  ${CYAN}%-50s${NC} targeted from %s unique IPs\n" "$username" "$count"
        done
    fi
    
    # Password analysis (only for colon-separated format)
    if [[ "$is_tab_format" != "yes" ]]; then
        echo -e "\n${YELLOW}Password Pattern Analysis:${NC}"
        local common_passwords=$(awk -F: '{print $2}' "$file" | sort | uniq -c | sort -nr | head -10 || true)
        echo -e "${RED}Most Common Passwords Attempted:${NC}"
        (echo "$common_passwords" || true) | while read count password; do
            printf "  ${MAGENTA}%-50s${NC} %s times\n" "$(echo $password | cut -c1-50)" "$count"
        done
    fi
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Security event analysis
    local credential_stuffing_indicators=$total_attempts
    local password_spray="N/A"
    if [[ "$is_tab_format" != "yes" ]]; then
        password_spray=$(echo "$common_passwords" | head -1 | awk '{print $1}')
    fi
    local targeted_accounts
    if [[ "$is_tab_format" == "yes" ]]; then
        targeted_accounts=$(awk -F$'\t' '{print $3}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
    else
        targeted_accounts=$(awk -F: '{print $1}' "$file" | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
    fi
    
    echo -e "\n${YELLOW}Attack Pattern Analysis:${NC}"
    print_result "Total Credential Attempts" "${credential_stuffing_indicators:-0}" "$RED"
    print_result "Most Reused Password (count)" "${password_spray:-0} times" "$RED"
    print_result "Highest Targeted Account" "${targeted_accounts:-0} attempts" "$RED"
    
    # Attack type identification
    echo -e "\n${YELLOW}Attack Type Classification:${NC}"
    local unique_pass
    local pass_to_attempt_ratio="N/A"
    if [[ "$is_tab_format" != "yes" ]]; then
        unique_pass=$(awk -F: '{print $2}' "$file" | sort -u | wc -l | tr -d ' ')
        unique_pass=${unique_pass:-0}
        if [[ $total_attempts -gt 0 ]]; then
            pass_to_attempt_ratio=$(awk -v up="$unique_pass" -v ta="$total_attempts" 'BEGIN {printf "%.2f", up/ta}')
        else
            pass_to_attempt_ratio="0.00"
        fi
    else
        unique_pass="N/A"
    fi
    
    if [[ "$is_tab_format" != "yes" ]]; then
        local ratio_check=$(awk -v r="$pass_to_attempt_ratio" 'BEGIN {if (r > 0.8) print "high"; else if (r < 0.1) print "low"; else print "mixed"}')
        
        if [[ "$ratio_check" == "high" ]]; then
            print_result "Attack Pattern" "Credential Stuffing (high password diversity)" "$RED"
        elif [[ "$ratio_check" == "low" ]]; then
            print_result "Attack Pattern" "Password Spraying (low password diversity)" "$RED"
        else
            print_result "Attack Pattern" "Mixed Attack Strategy" "$YELLOW"
        fi
        
        print_result "Unique Passwords Tried" "$unique_pass"
        print_result "Password Diversity Ratio" "$pass_to_attempt_ratio"
    else
        print_result "Attack Pattern" "Username enumeration (no password data)" "$YELLOW"
    fi
    
    # Temporal analysis
    echo -e "\n${YELLOW}Temporal Attack Analysis:${NC}"
    if grep -q '^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}' "$file"; then
        local attack_days
        if [[ "$is_tab_format" == "yes" ]]; then
            attack_days=$(awk -F$'\t' '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u | wc -l | tr -d ' ')
        else
            attack_days=$(awk -F: '{print $1}' "$file" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | sort -u | wc -l | tr -d ' ')
        fi
        attack_days=${attack_days:-1}
        local avg_daily_attempts=$((total_attempts / attack_days))
        print_result "Attack Duration (days)" "$attack_days" "$YELLOW"
        print_result "Average Daily Attempts" "$avg_daily_attempts" "$RED"
    fi
    
    # Risk indicators
    echo -e "\n${YELLOW}Risk Indicators:${NC}"
    local high_value_targets
    if [[ "$is_tab_format" == "yes" ]]; then
        high_value_targets=$(awk -F$'\t' '{print $3}' "$file" | grep -iE "admin|root|administrator|user" | wc -l | tr -d ' ')
    else
        high_value_targets=$(awk -F: '{print $1}' "$file" | grep -iE "admin|root|administrator|user" | wc -l | tr -d ' ')
    fi
    high_value_targets=${high_value_targets:-0}
    print_result "High-Value Account Attempts" "${high_value_targets}" "$RED"
    
    # IP distribution analysis
    local unique_source_ips
    if [[ "$is_tab_format" == "yes" ]]; then
        unique_source_ips=$(awk -F$'\t' '{print $2}' "$file" | sort -u | wc -l | tr -d ' ')
    else
        unique_source_ips=$(awk -F: '{print $3}' "$file" | sort -u | wc -l | tr -d ' ')
    fi
    unique_source_ips=${unique_source_ips:-0}
    
    local distributed
    local distributed_color
    if [[ $unique_source_ips -gt 50 ]]; then
        distributed="YES - Botnet suspected"
        distributed_color="$RED"
    else
        distributed="NO"
        distributed_color="$GREEN"
    fi
    print_result "Attack Source IPs" "$unique_source_ips"
    print_result "Distributed Attack" "$distributed" "$distributed_color"
    
    # Overall risk assessment
    local total_security_score=$((total_attempts / 100 + unique_source_ips / 10))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 50 ]]; then
        print_result "Risk Level" "CRITICAL - Large-scale credential attack" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Massive credential stuffing campaign (${total_attempts} attempts)${NC}"
        echo -e "${RED}     • Likely compromised credential database in use${NC}"
        echo -e "${RED}     • Force password resets for affected accounts${NC}"
    elif [[ $total_security_score -gt 20 ]]; then
        print_result "Risk Level" "HIGH - Sustained attack activity" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Significant login attempts (${total_attempts})${NC}"
        echo -e "${YELLOW}     • Enable account lockout policies${NC}"
        echo -e "${YELLOW}     • Implement CAPTCHA or MFA${NC}"
    elif [[ $total_security_score -gt 5 ]]; then
        print_result "Risk Level" "MEDIUM - Moderate threat activity" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY DETECTED:${NC}"
        echo -e "${CYAN}     • Typical brute force probing${NC}"
        echo -e "${CYAN}     • Monitor for escalation${NC}"
    else
        print_result "Risk Level" "LOW - Minimal threat" "$GREEN"
        echo -e "\n${GREEN}  ✅ LOW THREAT PROFILE:${NC}"
        echo -e "${GREEN}     • Limited attack activity${NC}"
        echo -e "${GREEN}     • Standard monitoring sufficient${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $total_attempts -gt 1000 ]]; then
        echo -e "${RED}  🔒 URGENT: Implement account lockout after N failed attempts${NC}"
        echo -e "${RED}  🔑 URGENT: Force MFA/2FA for all accounts${NC}"
    fi
    if [[ $high_value_targets -gt 100 ]]; then
        echo -e "${RED}  ⚠️  High-value accounts under attack - enhance monitoring${NC}"
    fi
    if [[ $unique_source_ips -gt 50 ]]; then
        echo -e "${YELLOW}  🌐 Botnet activity detected - implement CAPTCHA${NC}"
    fi
    echo -e "${CYAN}  ✓ Enable comprehensive login attempt logging${NC}"
    echo -e "${CYAN}  ✓ Consider IP reputation filtering${NC}"
}

# VSFTPD log analysis
analyze_vsftpd() {
    local file="$1"
    print_header "VSFTPD (FTP SERVER) LOG ANALYSIS"
    
    # Basic metrics
    local total_entries=$(grep -v '^#\|^$' "$file" | wc -l)
    print_result "Total Log Entries" "$total_entries"
    
    # Unique users
    echo -e "\n${YELLOW}User Analysis:${NC}"
    local all_users=$(grep -oE "\[([a-zA-Z0-9_-]+)\]" "$file" | tr -d '[]' | sort -u)
    local user_count=$(echo "$all_users" | wc -l)
    print_result "Unique FTP Users" "$user_count"
    
    echo -e "\n${CYAN}FTP Users:${NC}"
    echo "$all_users" | while read username; do
        local login_count=$(grep "\[$username\]" "$file" | grep -i "OK LOGIN" | wc -l)
        printf "  ${GREEN}%-50s${NC} %s logins\n" "$username" "$login_count"
    done
    
    # ftpuser specific analysis
    if echo "$all_users" | grep -q "ftpuser"; then
        echo -e "\n${YELLOW}ftpuser Detailed Analysis:${NC}"
        
        # First login IP
        local first_login_ip=$(grep "\[ftpuser\]" "$file" | grep -i "OK LOGIN" | head -1 | \
            grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
        print_result "First Login IP" "${first_login_ip:-Not found}"
        
        # Directory creation analysis
        local first_dir=$(grep "\[ftpuser\]" "$file" | grep -i "MKD\|MKDIR" | head -1 | \
            awk '{print $NF}' | tr -d '"')
        local last_dir=$(grep "\[ftpuser\]" "$file" | grep -i "MKD\|MKDIR" | tail -1 | \
            awk '{print $NF}' | tr -d '"')
        print_result "First Directory Created" "${first_dir:-None}"
        print_result "Last Directory Created" "${last_dir:-None}"
        
        # File extension analysis
        echo -e "\n${CYAN}ftpuser File Extensions:${NC}"
        grep "\[ftpuser\]" "$file" | grep -oE "\.[a-zA-Z0-9]{2,4}" | \
            tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -nr | head -10 | \
        while read count ext; do
            printf "  ${MAGENTA}%-50s${NC} %s files\n" "$ext" "$count"
        done
        
        local most_used_ext=$(grep "\[ftpuser\]" "$file" | grep -oE "\.[a-zA-Z0-9]{2,4}" | \
            tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
        echo
        print_result "Most Used Extension" "${most_used_ext:-None}" "$GREEN"
        
        # Bytes uploaded/downloaded
        local bytes_uploaded=$(grep "\[ftpuser\]" "$file" | grep -i "STOR\|OK UPLOAD" | \
            grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
        local bytes_downloaded=$(grep "\[ftpuser\]" "$file" | grep -i "RETR\|OK DOWNLOAD" | \
            grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
        print_result "Total Bytes Uploaded" "$bytes_uploaded bytes"
        print_result "Total Bytes Downloaded" "$bytes_downloaded bytes"
    fi
    
    # Other users analysis
    local other_users=$(echo "$all_users" | grep -v "ftpuser")
    if [[ -n "$other_users" ]]; then
        echo -e "\n${YELLOW}Other Users Analysis:${NC}"
        echo "$other_users" | while read other_user; do
            if [[ -n "$other_user" ]]; then
                echo -e "\n${CYAN}User: $other_user${NC}"
                
                # Login IP
                local user_ip=$(grep "\[$other_user\]" "$file" | grep -i "OK LOGIN" | head -1 | \
                    grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
                print_result "Login IP" "${user_ip:-Unknown}"
                
                # Bytes transferred
                local user_upload=$(grep "\[$other_user\]" "$file" | grep -i "STOR\|OK UPLOAD" | \
                    grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
                local user_download=$(grep "\[$other_user\]" "$file" | grep -i "RETR\|OK DOWNLOAD" | \
                    grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
                print_result "Total Uploaded" "$user_upload bytes"
                print_result "Total Downloaded" "$user_download bytes"
            fi
        done
    fi
    
    # Suspicious login detection (login with no activity)
    echo -e "\n${YELLOW}Security Analysis:${NC}"
    echo -e "${RED}Suspicious Logins (No Subsequent Activity):${NC}"
    
    # Get all login IPs and check for activity
    grep -i "OK LOGIN" "$file" | while read login_line; do
        local login_ip=$(echo "$login_line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
        local login_user=$(echo "$login_line" | grep -oE "\[[a-zA-Z0-9_-]+\]" | tr -d '[]')
        
        # Check for any activity after login from this IP/user combination
        local activity_count=$(grep "$login_ip" "$file" | grep "\[$login_user\]" | \
            grep -v "OK LOGIN" | grep -i "RETR\|STOR\|LIST\|CWD\|MKD" | wc -l)
        
        if [[ $activity_count -eq 0 ]]; then
            printf "  ${RED}%-25s${NC} ${YELLOW}%-25s${NC} (No file operations detected)\n" "$login_ip" "[$login_user]"
        fi
    done | head -10
    
    # Command analysis
    echo -e "\n${YELLOW}FTP Command Usage:${NC}"
    grep -oE "(RETR|STOR|LIST|CWD|MKD|RMD|DELE|PWD|USER|PASS)" "$file" | \
        sort | uniq -c | sort -nr | \
    while read count cmd; do
        printf "  ${CYAN}%-50s${NC} %s times\n" "$cmd" "$count"
    done
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Security event analysis
    local failed_logins=$(grep -i "FAIL LOGIN" "$file" | wc -l)
    local anonymous_attempts=$(grep -i "anonymous" "$file" | wc -l)
    local upload_count=$(grep -i "STOR\|OK UPLOAD" "$file" | wc -l)
    local download_count=$(grep -i "RETR\|OK DOWNLOAD" "$file" | wc -l)
    local delete_operations=$(grep -i "DELE\|RMD" "$file" | wc -l)
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Failed Login Attempts" "${failed_logins:-0}" "$RED"
    print_result "Anonymous Access Attempts" "${anonymous_attempts:-0}" "$YELLOW"
    print_result "File Upload Operations" "${upload_count:-0}" "$CYAN"
    print_result "File Download Operations" "${download_count:-0}" "$CYAN"
    print_result "Delete Operations" "${delete_operations:-0}" "$RED"
    
    # Data exfiltration analysis
    echo -e "\n${YELLOW}Data Transfer Risk Analysis:${NC}"
    local total_bytes_up=$(grep -i "STOR\|OK UPLOAD" "$file" | grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
    local total_bytes_down=$(grep -i "RETR\|OK DOWNLOAD" "$file" | grep -oE "[0-9]+ bytes" | awk '{sum+=$1} END {print sum+0}')
    local transfer_ratio=$(echo "scale=2; $total_bytes_down / ($total_bytes_up + 1)" | bc 2>/dev/null || echo "0")
    
    print_result "Total Bytes Uploaded" "$total_bytes_up bytes" "$YELLOW"
    print_result "Total Bytes Downloaded" "$total_bytes_down bytes" "$YELLOW"
    print_result "Download/Upload Ratio" "$transfer_ratio" "$([ $(echo "$transfer_ratio > 10" | bc -l 2>/dev/null || echo 0) -eq 1 ] && echo $RED || echo $GREEN)"
    
    if (( $(echo "$transfer_ratio > 10" | bc -l 2>/dev/null || echo 0) )); then
        echo -e "${RED}  ⚠️  WARNING: High download ratio suggests data exfiltration${NC}"
    fi
    
    # Suspicious file operations
    echo -e "\n${YELLOW}Suspicious Activity Indicators:${NC}"
    local executable_uploads=$(grep -i "STOR" "$file" | grep -iE "\.(exe|sh|bat|ps1|dll|so|cmd)" | wc -l)
    local archive_uploads=$(grep -i "STOR" "$file" | grep -iE "\.(zip|rar|tar|gz|7z)" | wc -l)
    local webshell_indicators=$(grep -i "STOR" "$file" | grep -iE "\.(php|asp|aspx|jsp)" | wc -l)
    
    print_result "Executable File Uploads" "${executable_uploads:-0}" "$RED"
    print_result "Archive File Uploads" "${archive_uploads:-0}" "$YELLOW"
    print_result "Web Shell Indicators" "${webshell_indicators:-0}" "$RED"
    
    # Access pattern analysis
    echo -e "\n${YELLOW}Access Pattern Analysis:${NC}"
    local unique_ips=$(grep -i "OK LOGIN" "$file" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u | wc -l)
    local suspicious_logins=$(grep -i "OK LOGIN" "$file" | wc -l)
    local login_no_activity=$(grep -i "OK LOGIN" "$file" | while read line; do
        ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
        user=$(echo "$line" | grep -oE "\[[^]]+\]" | tr -d '[]')
        act=$(grep "$ip" "$file" | grep "\[$user\]" | grep -v "OK LOGIN" | grep -iE "RETR|STOR|LIST" | wc -l)
        [ $act -eq 0 ] && echo "1" || echo "0"
    done | grep -c "1")
    
    print_result "Unique Login IPs" "$unique_ips"
    print_result "Total Successful Logins" "$suspicious_logins" "$GREEN"
    print_result "Logins Without Activity" "${login_no_activity:-0}" "$RED"
    
    # Temporal analysis
    echo -e "\n${YELLOW}Temporal Security Analysis:${NC}"
    local after_hours=$(grep -E "(2[2-3]|0[0-5]):[0-9]{2}:[0-9]{2}" "$file" | grep -i "OK LOGIN" | wc -l)
    print_result "After-Hours Access (10PM-6AM)" "${after_hours:-0}" "$YELLOW"
    
    # Overall risk assessment
    local total_security_score=$((failed_logins / 10 + executable_uploads * 10 + webshell_indicators * 20 + login_no_activity * 5))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 50 ]]; then
        print_result "Risk Level" "CRITICAL - Potential compromise detected" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Suspicious file uploads detected${NC}"
        echo -e "${RED}     • Possible web shell deployment (${webshell_indicators})${NC}"
        echo -e "${RED}     • Immediate forensic investigation required${NC}"
    elif [[ $total_security_score -gt 20 ]]; then
        print_result "Risk Level" "HIGH - Suspicious activity detected" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Unusual file transfer patterns${NC}"
        echo -e "${YELLOW}     • Review uploaded files for malware${NC}"
        echo -e "${YELLOW}     • Enhanced monitoring recommended${NC}"
    elif [[ $total_security_score -gt 5 ]]; then
        print_result "Risk Level" "MEDIUM - Monitor activity" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY:${NC}"
        echo -e "${CYAN}     • Normal FTP usage patterns${NC}"
        echo -e "${CYAN}     • Continue standard monitoring${NC}"
    else
        print_result "Risk Level" "LOW - Normal operation" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION:${NC}"
        echo -e "${GREEN}     • Legitimate file transfers${NC}"
        echo -e "${GREEN}     • No significant threats detected${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $webshell_indicators -gt 0 ]]; then
        echo -e "${RED}  🚨 URGENT: Scan server for web shells immediately${NC}"
    fi
    if [[ $executable_uploads -gt 0 ]]; then
        echo -e "${RED}  ⚠️  Review all executable uploads for malware${NC}"
    fi
    if [[ $anonymous_attempts -gt 10 ]]; then
        echo -e "${YELLOW}  🔒 Disable anonymous FTP access${NC}"
    fi
    if [[ $login_no_activity -gt 3 ]]; then
        echo -e "${YELLOW}  🔍 Investigate logins with no activity (recon?)${NC}"
    fi
    echo -e "${CYAN}  ✓ Enable FTP logging for all file operations${NC}"
    echo -e "${CYAN}  ✓ Consider switching to SFTP for encryption${NC}"
}

# Web access log analysis (access.log)
analyze_access_log() {
    local file="$1"
    print_header "WEB ACCESS LOG ANALYSIS"
    
    # Basic metrics
    local total_requests=$(grep -v '^#\|^$' "$file" | wc -l)
    print_result "Total HTTP Requests" "$total_requests"
    
    # Unique IP addresses
    local unique_ips=$(awk '{print $1}' "$file" | sort -u | wc -l)
    print_result "Unique IP Addresses" "$unique_ips"
    
    # HTTP status codes
    echo -e "\n${YELLOW}HTTP Status Code Analysis:${NC}"
    local status_200=$(grep -o '" [0-9][0-9][0-9] ' "$file" | grep '" 200 ' | wc -l)
    local status_400=$(grep -o '" [0-9][0-9][0-9] ' "$file" | grep '" 400 ' | wc -l)
    local status_404=$(grep -o '" [0-9][0-9][0-9] ' "$file" | grep '" 404 ' | wc -l)
    local status_500=$(grep -o '" [0-9][0-9][0-9] ' "$file" | grep '" 500 ' | wc -l)
    
    print_result "200 (Success) Responses" "$status_200" "$GREEN"
    print_result "400 (Bad Request) Responses" "$status_400" "$RED"
    print_result "404 (Not Found) Responses" "$status_404" "$YELLOW"
    print_result "500 (Server Error) Responses" "$status_500" "$RED"
    
    # All status codes breakdown
    echo -e "\n${CYAN}Complete Status Code Breakdown:${NC}"
    grep -o '" [0-9][0-9][0-9] ' "$file" | awk '{print $2}' | sort | uniq -c | sort -nr | \
    while read count code; do
        printf "  ${BLUE}%-50s${NC} %s requests\n" "$code" "$count"
    done
    
    # HTTP methods
    echo -e "\n${YELLOW}HTTP Method Distribution:${NC}"
    grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)' "$file" | tr -d '"' | \
        sort | uniq -c | sort -nr | \
    while read count method; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$method" "$count"
    done
    
    local most_common_method=$(grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)' "$file" | \
        tr -d '"' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
    local second_common_method=$(grep -oE '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)' "$file" | \
        tr -d '"' | sort | uniq -c | sort -nr | head -2 | tail -1 | awk '{print $2}')
    echo
    print_result "Most Common Method" "$most_common_method" "$GREEN"
    print_result "Second Most Common Method" "$second_common_method" "$CYAN"
    
    # User agent analysis
    echo -e "\n${YELLOW}User Agent Analysis:${NC}"
    
    # Googlebot version
    local googlebot=$(grep -i "Googlebot" "$file" | head -1 | grep -oE "Googlebot/[0-9.]+" | head -1)
    print_result "Googlebot Version" "${googlebot:-Not detected}"
    
    # Firefox versions
    echo -e "\n${CYAN}Firefox Version Analysis:${NC}"
    grep -i "Firefox" "$file" | grep -oE "Firefox/[0-9.]+" | sort | uniq -c | sort -nr | head -10 | \
    while read count version; do
        printf "  ${MAGENTA}%-50s${NC} %s requests\n" "$version" "$count"
    done
    
    local top_firefox=$(grep -i "Firefox" "$file" | grep -oE "Firefox/[0-9.]+" | \
        sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
    if [[ -n "$top_firefox" ]]; then
        echo
        print_result "Most Popular Firefox Version" "$top_firefox" "$GREEN"
    fi
    
    # Interesting requests
    echo -e "\n${YELLOW}Interesting/Notable Requests:${NC}"
    
    # Doorbell access
    local doorbell_ip=$(grep -i "doorbell" "$file" | head -1 | awk '{print $1}')
    if [[ -n "$doorbell_ip" ]]; then
        print_result "Doorbell Access IP" "$doorbell_ip" "$CYAN"
    fi
    
    # Shellshock vulnerability attempts
    local shellshock_ip=$(grep -i "() {" "$file" | head -1 | awk '{print $1}')
    if [[ -n "$shellshock_ip" ]]; then
        print_result "Shellshock Exploit Attempt" "$shellshock_ip" "$RED"
    fi
    
    # Binary/malformed requests
    local binary_requests=$(grep -c "\\x" "$file")
    print_result "Binary/Malformed Requests" "$binary_requests" "$RED"
    
    if [[ $binary_requests -gt 0 ]]; then
        echo -e "\n${RED}Specific Binary/Malformed Request Analysis:${NC}"
        grep "\\x" "$file" | while read line; do
            local request=$(echo "$line" | grep -oE '"[^"]+"' | head -2 | tail -1)
            local ip=$(echo "$line" | awk '{print $1}')
            if [[ -n "$request" ]]; then
                printf "  ${YELLOW}%-25s${NC} %s\n" "$ip" "$(echo $request | cut -c1-60)"
            fi
        done | head -5
        
        # Count specific binary pattern
        local specific_pattern=$(grep -c "\\x04\\x01\\x00P" "$file")
        print_result "Requests for \\x04\\x01\\x00P pattern" "$specific_pattern" "$RED"
    fi
    
    # Top requested paths
    echo -e "\n${YELLOW}Top Requested Paths:${NC}"
    grep -oE '"(GET|POST|PUT|DELETE|HEAD) [^ ]+' "$file" | awk '{print $2}' | \
        sort | uniq -c | sort -nr | head -15 | \
    while read count path; do
        printf "  ${CYAN}%-60s${NC} %s requests\n" "$(echo $path | cut -c1-60)" "$count"
    done
    
    # Top client IPs
    echo -e "\n${YELLOW}Top Client IP Addresses:${NC}"
    awk '{print $1}' "$file" | sort | uniq -c | sort -nr | head -10 | \
    while read count ip; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$ip" "$count"
    done
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Security event analysis
    local total_errors=$((status_400 + status_404 + status_500))
    local sql_injection=$(grep -ic "union.*select\|' or\|1=1\|<script\|alert(" "$file")
    local path_traversal=$(grep -c "\.\." "$file")
    local command_injection=$(grep -c "();\||\|&\|\\x" "$file")
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Total Error Responses" "$total_errors" "$RED"
    print_result "SQL Injection Attempts" "${sql_injection:-0}" "$RED"
    print_result "Path Traversal Attempts" "${path_traversal:-0}" "$RED"
    print_result "Command Injection Attempts" "${command_injection:-0}" "$RED"
    print_result "Shellshock Attempts" "$(grep -c '() {' "$file")" "$RED"
    
    # Bot and scanner detection
    echo -e "\n${YELLOW}Bot & Scanner Analysis:${NC}"
    local bot_traffic=$(grep -icE "bot|crawler|spider|scan" "$file")
    local vulnerability_scans=$(grep -icE "nikto|nmap|sqlmap|acunetix|nessus" "$file")
    local suspicious_ua=$(grep -c '"\-"' "$file")
    
    print_result "Bot/Crawler Traffic" "${bot_traffic:-0}" "$CYAN"
    print_result "Vulnerability Scanner Requests" "${vulnerability_scans:-0}" "$RED"
    print_result "Missing User-Agent Requests" "${suspicious_ua:-0}" "$YELLOW"
    
    # Attack surface analysis
    echo -e "\n${YELLOW}Attack Surface Analysis:${NC}"
    local admin_access=$(grep -ic "admin\|phpmyadmin\|wp-admin\|cpanel" "$file")
    local sensitive_paths=$(grep -icE "config|backup|\.env|\.git|database" "$file")
    local exploit_attempts=$(grep -icE "exploit|payload|shell|cmd" "$file")
    
    print_result "Admin Panel Access Attempts" "${admin_access:-0}" "$RED"
    print_result "Sensitive Path Probes" "${sensitive_paths:-0}" "$RED"
    print_result "Exploit Payload Attempts" "${exploit_attempts:-0}" "$RED"
    
    # Rate-based anomalies
    echo -e "\n${YELLOW}Rate-Based Anomaly Detection:${NC}"
    local high_volume_ips=$(awk '{print $1}' "$file" | sort | uniq -c | awk '$1>100' | wc -l)
    local rapid_fire=$(awk '{print $4}' "$file" | sed 's/\[//;s/:.*//g' | sort | uniq -c | awk '$1>500' | wc -l)
    
    print_result "High-Volume IPs (>100 req)" "${high_volume_ips:-0}" "$YELLOW"
    print_result "Rapid-Fire Time Windows" "${rapid_fire:-0}" "$RED"
    
    # DDoS indicators
    if [[ $high_volume_ips -gt 10 || $rapid_fire -gt 5 ]]; then
        echo -e "\n${RED}  ⚠️  DDoS Attack Indicators Detected!${NC}"
        print_result "DDoS Likelihood" "HIGH" "$RED"
    fi
    
    # Malicious file access
    echo -e "\n${YELLOW}Malicious File Access Attempts:${NC}"
    local webshell_access=$(grep -icE "\.php\?|eval\(|base64_decode|exec\(" "$file")
    local crypto_mining=$(grep -ic "coinhive\|cryptonight\|xmr" "$file")
    
    print_result "Web Shell Access Attempts" "${webshell_access:-0}" "$RED"
    print_result "Crypto Mining Indicators" "${crypto_mining:-0}" "$RED"
    
    # Overall risk assessment
    local total_security_score=$((sql_injection * 5 + path_traversal * 3 + vulnerability_scans * 10 + admin_access / 10 + exploit_attempts * 5))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 100 ]]; then
        print_result "Risk Level" "CRITICAL - Active attack in progress" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Multiple attack vectors detected${NC}"
        echo -e "${RED}     • SQL injection attempts: ${sql_injection}${NC}"
        echo -e "${RED}     • Vulnerability scanning: ${vulnerability_scans}${NC}"
        echo -e "${RED}     • Immediate WAF/IPS deployment required${NC}"
    elif [[ $total_security_score -gt 30 ]]; then
        print_result "Risk Level" "HIGH - Significant attack activity" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Active reconnaissance detected${NC}"
        echo -e "${YELLOW}     • Multiple exploit attempts${NC}"
        echo -e "${YELLOW}     • Enhanced security measures needed${NC}"
    elif [[ $total_security_score -gt 10 ]]; then
        print_result "Risk Level" "MEDIUM - Moderate threat activity" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY:${NC}"
        echo -e "${CYAN}     • Typical scanning/probing activity${NC}"
        echo -e "${CYAN}     • Standard web application threats${NC}"
    else
        print_result "Risk Level" "LOW - Normal web traffic" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL TRAFFIC PROFILE:${NC}"
        echo -e "${GREEN}     • Legitimate web requests${NC}"
        echo -e "${GREEN}     • No significant threats detected${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ $sql_injection -gt 10 ]]; then
        echo -e "${RED}  🛡️  URGENT: Deploy Web Application Firewall (WAF)${NC}"
        echo -e "${RED}  🔒 URGENT: Review database security and parameterized queries${NC}"
    fi
    if [[ $vulnerability_scans -gt 5 ]]; then
        echo -e "${RED}  🔍 Active vulnerability scanning - patch known vulnerabilities${NC}"
    fi
    if [[ $admin_access -gt 50 ]]; then
        echo -e "${YELLOW}  🔐 Restrict admin panel access by IP or VPN${NC}"
    fi
    if [[ $shellshock_ip ]]; then
        echo -e "${RED}  ⚠️  Shellshock exploit detected - update bash immediately${NC}"
    fi
    if [[ $high_volume_ips -gt 10 ]]; then
        echo -e "${YELLOW}  🚦 Implement rate limiting to prevent abuse${NC}"
    fi
    echo -e "${CYAN}  ✓ Keep web server and applications updated${NC}"
    echo -e "${CYAN}  ✓ Enable ModSecurity or similar WAF${NC}"
    echo -e "${CYAN}  ✓ Implement IP reputation filtering${NC}"
}

# SQLite browser database analysis
analyze_sqlite() {
    local file="$1"
    print_header "SQLITE DATABASE ANALYSIS (Browser History)"
    
    # Check if sqlite3 is available
    if ! command -v sqlite3 &> /dev/null; then
        print_result "Error" "sqlite3 command not found. Please install sqlite3." "$RED"
        return
    fi
    
    # Check if it's a valid SQLite database
    if ! sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table';" &> /dev/null; then
        print_result "Error" "Invalid SQLite database or corrupted file" "$RED"
        return
    fi
    
    # List tables
    echo -e "${YELLOW}Database Tables:${NC}"
    sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table';" | while read table; do
        echo "  ${CYAN}- $table${NC}"
    done
    
    # Browser history analysis
    echo -e "\n${YELLOW}Browser History Analysis:${NC}"
    
    # Check if common browser tables exist
    local has_history=$(sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%hist%';" | wc -l)
    local has_urls=$(sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE '%url%' OR name='moz_places');" | wc -l)
    
    if [[ $has_history -gt 0 || $has_urls -gt 0 ]]; then
        # Try to find the URL table
        local url_table=$(sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE '%url%' OR name='moz_places' OR name='urls');" | head -1)
        
        if [[ -n "$url_table" ]]; then
            local total_urls=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table;" 2>/dev/null || echo "0")
            print_result "Total URLs in Database" "$total_urls"
            
            # Craigslist search
            echo -e "\n${YELLOW}Craigslist Activity:${NC}"
            local craigslist_search=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%craigslist%' ORDER BY id;" 2>/dev/null | \
                grep -oE "(query|search|q)=[^&]+" | cut -d= -f2 | head -1)
            if [[ -n "$craigslist_search" ]]; then
                print_result "Craigslist Search Query" "$(echo $craigslist_search | sed 's/+/ /g' | sed 's/%20/ /g')" "$GREEN"
            else
                # Try alternative patterns
                sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%craigslist%';" 2>/dev/null | head -5 | while read url; do
                    if echo "$url" | grep -q "search\|query\|q="; then
                        echo "  ${CYAN}Found: $(echo $url | cut -c1-80)${NC}"
                    fi
                done
            fi
            
            # Bitcoin price detection
            echo -e "\n${YELLOW}Bitcoin/Cryptocurrency Activity:${NC}"
            local btc_price=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%bitcoin%' OR url LIKE '%btc%' OR url LIKE '%coinbase%' OR url LIKE '%blockchain%';" 2>/dev/null | \
                grep -oE "[0-9]+\.[0-9]+" | head -1)
            if [[ -n "$btc_price" ]]; then
                print_result "Bitcoin Price Reference" "$$btc_price" "$GREEN"
            fi
            
            # Bitcoin exchanges
            local btc_exchanges=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%coinbase%' OR url LIKE '%kraken%' OR url LIKE '%binance%' OR url LIKE '%bitstamp%';" 2>/dev/null)
            if [[ -n "$btc_exchanges" ]]; then
                echo -e "${CYAN}Bitcoin Exchanges Visited:${NC}"
                (echo "$btc_exchanges" | while read exchange_url; do
                    local exchange_name=$(echo "$exchange_url" | grep -oE "(coinbase|kraken|binance|bitstamp)" | head -1)
                    if [[ -n "$exchange_name" ]]; then
                        printf "  ${GREEN}%-25s${NC} %s\n" "$exchange_name" "$(echo $exchange_url | cut -c1-60)"
                    fi
                done | head -5 || true)
                
                # Try to extract login email
                local login_email=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%login%' OR url LIKE '%signin%';" 2>/dev/null | \
                    grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -1)
                if [[ -n "$login_email" ]]; then
                    print_result "Email Used for Login" "$login_email" "$CYAN"
                fi
            fi
            
            # Bitcoin transaction ID
            local btc_txid=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%blockchain%' OR url LIKE '%tx%' OR url LIKE '%transaction%';" 2>/dev/null | \
                grep -oE "[a-f0-9]{64}" | head -1)
            if [[ -n "$btc_txid" ]]; then
                print_result "Bitcoin Transaction ID" "$btc_txid" "$GREEN"
            fi
            
            # Bitcoin amounts
            local btc_amounts=$(sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%blockchain%' OR url LIKE '%bitcoin%';" 2>/dev/null | \
                grep -oE "[0-9]+\.[0-9]+ BTC" | head -1)
            if [[ -n "$btc_amounts" ]]; then
                print_result "Bitcoin Amount Referenced" "$btc_amounts" "$GREEN"
            fi
            
            # Bitcoin addresses
            echo -e "\n${YELLOW}Bitcoin Addresses Found:${NC}"
            (sqlite3 "$file" "SELECT url FROM $url_table WHERE url LIKE '%blockchain%' OR url LIKE '%bitcoin%' OR url LIKE '%address%';" 2>/dev/null | \
                grep -oE "[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,87}" | sort -u | head -10 || true) | \
            while read btc_addr; do
                printf "  ${GREEN}%-50s${NC}\n" "$btc_addr"
            done
            
            # Top domains visited
            echo -e "\n${YELLOW}Top Domains Visited:${NC}"
            (sqlite3 "$file" "SELECT url FROM $url_table;" 2>/dev/null | \
                grep -oE "https?://[^/]+" | sed 's|https\?://||' | sed 's|www\.||' | \
                sort | uniq -c | sort -nr | head -15 || true) | \
            while read count domain; do
                printf "  ${CYAN}%-50s${NC} %s visits\n" "$domain" "$count"
            done
        fi
    else
        print_result "Note" "No standard browser history tables found" "$YELLOW"
    fi
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Privacy and security analysis
    echo -e "\n${YELLOW}Privacy & Security Analysis:${NC}"
    
    if [[ $has_history -gt 0 || $has_urls -gt 0 ]]; then
        local url_table=$(sqlite3 "$file" "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE '%url%' OR name='moz_places' OR name='urls');" | head -1)
        
        if [[ -n "$url_table" ]]; then
            # Sensitive site access
            local banking_sites=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%bank%' OR url LIKE '%paypal%' OR url LIKE '%chase%';" 2>/dev/null || echo "0")
            local crypto_sites=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%bitcoin%' OR url LIKE '%coinbase%' OR url LIKE '%blockchain%' OR url LIKE '%crypto%';" 2>/dev/null || echo "0")
            local social_media=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%facebook%' OR url LIKE '%twitter%' OR url LIKE '%instagram%' OR url LIKE '%linkedin%';" 2>/dev/null || echo "0")
            local dark_web=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%.onion%';" 2>/dev/null || echo "0")
            
            print_result "Banking/Financial Sites" "${banking_sites:-0} visits" "$YELLOW"
            print_result "Cryptocurrency Sites" "${crypto_sites:-0} visits" "$CYAN"
            print_result "Social Media Sites" "${social_media:-0} visits" "$CYAN"
            print_result "Dark Web (.onion) Sites" "${dark_web:-0} visits" "$([ ${dark_web:-0} -gt 0 ] && echo $RED || echo $GREEN)"
            
            # Suspicious activity indicators
            echo -e "\n${YELLOW}Suspicious Activity Indicators:${NC}"
            local hacking_tools=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%hack%' OR url LIKE '%exploit%' OR url LIKE '%payload%' OR url LIKE '%metasploit%';" 2>/dev/null || echo "0")
            local malware_sites=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%malware%' OR url LIKE '%virus%' OR url LIKE '%trojan%';" 2>/dev/null || echo "0")
            local phishing_indicators=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%verify%account%' OR url LIKE '%suspended%' OR url LIKE '%urgent%';" 2>/dev/null || echo "0")
            
            print_result "Hacking/Security Tool Sites" "${hacking_tools:-0} visits" "$RED"
            print_result "Malware-Related Sites" "${malware_sites:-0} visits" "$RED"
            print_result "Potential Phishing Sites" "${phishing_indicators:-0} visits" "$RED"
            
            # Data exfiltration risks
            echo -e "\n${YELLOW}Data Exfiltration Risk Analysis:${NC}"
            local file_sharing=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%dropbox%' OR url LIKE '%drive.google%' OR url LIKE '%mega.nz%' OR url LIKE '%mediafire%';" 2>/dev/null || echo "0")
            local paste_sites=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%pastebin%' OR url LIKE '%paste%';" 2>/dev/null || echo "0")
            local temporary_storage=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%temp%' OR url LIKE '%upload%' OR url LIKE '%file%';" 2>/dev/null || echo "0")
            
            print_result "File Sharing Services" "${file_sharing:-0} visits" "$YELLOW"
            print_result "Paste/Text Sharing Sites" "${paste_sites:-0} visits" "$YELLOW"
            print_result "Temp File Upload Sites" "${temporary_storage:-0} visits" "$RED"
            
            # Cryptocurrency transaction analysis
            if [[ ${crypto_sites:-0} -gt 0 ]]; then
                echo -e "\n${YELLOW}Cryptocurrency Activity Analysis:${NC}"
                local blockchain_lookups=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%blockchain.com%' OR url LIKE '%blockchair%' OR url LIKE '%etherscan%';" 2>/dev/null || echo "0")
                local exchange_logins=$(sqlite3 "$file" "SELECT COUNT(*) FROM $url_table WHERE url LIKE '%login%' AND (url LIKE '%coinbase%' OR url LIKE '%binance%' OR url LIKE '%kraken%');" 2>/dev/null || echo "0")
                
                print_result "Blockchain Explorer Lookups" "${blockchain_lookups:-0}" "$CYAN"
                print_result "Exchange Login Attempts" "${exchange_logins:-0}" "$YELLOW"
                
                if [[ ${exchange_logins:-0} -gt 0 ]]; then
                    echo -e "${YELLOW}  ⚠️  Cryptocurrency exchange access detected${NC}"
                fi
            fi
            
            # Overall risk assessment
            local total_security_score=$((hacking_tools * 10 + dark_web * 20 + malware_sites * 15 + paste_sites * 5))
            
            echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
            if [[ $total_security_score -gt 50 ]]; then
                print_result "Risk Level" "CRITICAL - Highly suspicious activity" "$RED"
                echo -e "\n${RED}  ⚠️  CRITICAL FINDINGS:${NC}"
                echo -e "${RED}     • Access to hacking/malware resources${NC}"
                if [[ ${dark_web:-0} -gt 0 ]]; then
                    echo -e "${RED}     • Dark web activity detected (${dark_web} .onion sites)${NC}"
                fi
                echo -e "${RED}     • Potential insider threat or compromised system${NC}"
                echo -e "${RED}     • Full forensic investigation recommended${NC}"
            elif [[ $total_security_score -gt 20 ]]; then
                print_result "Risk Level" "HIGH - Concerning browsing patterns" "$RED"
                echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
                echo -e "${YELLOW}     • Suspicious site categories accessed${NC}"
                echo -e "${YELLOW}     • Enhanced user monitoring required${NC}"
            elif [[ $total_security_score -gt 5 ]]; then
                print_result "Risk Level" "MEDIUM - Some concerning activity" "$YELLOW"
                echo -e "\n${CYAN}  ✓ MODERATE RISK:${NC}"
                echo -e "${CYAN}     • Mostly legitimate browsing${NC}"
                echo -e "${CYAN}     • Some security-related searches${NC}"
            else
                print_result "Risk Level" "LOW - Normal browsing activity" "$GREEN"
                echo -e "\n${GREEN}  ✅ NORMAL PROFILE:${NC}"
                echo -e "${GREEN}     • Standard web browsing patterns${NC}"
                echo -e "${GREEN}     • No significant security concerns${NC}"
            fi
            
            # Security recommendations
            echo -e "\n${YELLOW}Security Recommendations:${NC}"
            if [[ ${hacking_tools:-0} -gt 0 ]]; then
                echo -e "${RED}  🔍 Investigate user for unauthorized security testing${NC}"
            fi
            if [[ ${dark_web:-0} -gt 0 ]]; then
                echo -e "${RED}  🕵️  Dark web access detected - full investigation needed${NC}"
            fi
            if [[ ${file_sharing:-0} -gt 20 ]]; then
                echo -e "${YELLOW}  📤 High file sharing usage - monitor for data leakage${NC}"
            fi
            if [[ ${crypto_sites:-0} -gt 10 ]]; then
                echo -e "${YELLOW}  💰 Significant crypto activity - ensure compliance${NC}"
            fi
            echo -e "${CYAN}  ✓ Implement DNS filtering to block malicious domains${NC}"
            echo -e "${CYAN}  ✓ Enable browser history monitoring and DLP${NC}"
        fi
    fi
}

# Squid proxy log analysis
analyze_squid() {
    local file="$1"
    print_header "SQUID PROXY LOG ANALYSIS"
    
    # Basic metrics
    local total_requests=$(grep -v '^#\|^$' "$file" | wc -l)
    print_result "Total Proxy Requests" "$total_requests"
    
    # Year extraction
    local log_year=$(head -10 "$file" | awk '{print $1}' | head -1 | cut -c1-4)
    if [[ -n "$log_year" && "$log_year" =~ ^[0-9]{4}$ ]]; then
        print_result "Log Year" "$log_year" "$GREEN"
    else
        # Try timestamp conversion
        local timestamp=$(head -1 "$file" | awk '{print $1}' | cut -d. -f1)
        if [[ -n "$timestamp" ]]; then
            log_year=$(date -r "$timestamp" "+%Y" 2>/dev/null || echo "Unknown")
            print_result "Log Year" "$log_year"
        fi
    fi
    
    # Response time analysis
    echo -e "\n${YELLOW}Response Time Analysis:${NC}"
    local fastest=$(awk '{print $2}' "$file" | sort -n | head -1)
    local slowest=$(awk '{print $2}' "$file" | sort -n | tail -1)
    print_result "Fastest Request" "${fastest:-0} milliseconds" "$GREEN"
    print_result "Slowest Request" "${slowest:-0} milliseconds" "$RED"
    
    # Average response time
    local avg_time=$(awk '{sum+=$2; count++} END {printf "%.0f", sum/count}' "$file")
    print_result "Average Response Time" "${avg_time:-0} milliseconds" "$CYAN"
    
    # Unique IPs serviced
    local unique_clients=$(awk '{print $3}' "$file" | sort -u | wc -l)
    print_result "Unique Client IPs Serviced" "$unique_clients"
    
    # HTTP methods
    echo -e "\n${YELLOW}HTTP Method Distribution:${NC}"
    awk '{print $6}' "$file" | sort | uniq -c | sort -nr | \
    while read count method; do
        printf "  ${GREEN}%-50s${NC} %s requests\n" "$method" "$count"
    done
    
    local get_count=$(awk '{print $6}' "$file" | grep -c "^GET$")
    local post_count=$(awk '{print $6}' "$file" | grep -c "^POST$")
    echo
    print_result "GET Requests" "$get_count" "$GREEN"
    print_result "POST Requests" "$post_count" "$CYAN"
    
    # Client analysis
    echo -e "\n${YELLOW}Top Client IPs:${NC}"
    awk '{print $3}' "$file" | sort | uniq -c | sort -nr | head -10 | \
    while read count ip; do
        printf "  ${CYAN}%-50s${NC} %s requests\n" "$ip" "$count"
    done
    
    # Antivirus detection (User-Agent analysis)
    echo -e "\n${YELLOW}Security Software Detection:${NC}"
    
    # Check for specific client (192.168.0.224)
    local av_client="192.168.0.224"
    local av_useragent=$(grep "$av_client" "$file" | head -1 | awk -F'"' '{print $(NF-1)}')
    
    if [[ -n "$av_useragent" ]]; then
        print_result "Client $av_client User-Agent" "$av_useragent" "$CYAN"
        
        # Detect antivirus vendor
        if echo "$av_useragent" | grep -qi "symantec\|norton"; then
            print_result "Antivirus Vendor" "Symantec/Norton" "$GREEN"
        elif echo "$av_useragent" | grep -qi "mcafee"; then
            print_result "Antivirus Vendor" "McAfee" "$GREEN"
        elif echo "$av_useragent" | grep -qi "kaspersky"; then
            print_result "Antivirus Vendor" "Kaspersky" "$GREEN"
        elif echo "$av_useragent" | grep -qi "avast"; then
            print_result "Antivirus Vendor" "Avast" "$GREEN"
        elif echo "$av_useragent" | grep -qi "avg"; then
            print_result "Antivirus Vendor" "AVG" "$GREEN"
        elif echo "$av_useragent" | grep -qi "eset"; then
            print_result "Antivirus Vendor" "ESET" "$GREEN"
        elif echo "$av_useragent" | grep -qi "trend\|trendmicro"; then
            print_result "Antivirus Vendor" "Trend Micro" "$GREEN"
        elif echo "$av_useragent" | grep -qi "sophos"; then
            print_result "Antivirus Vendor" "Sophos" "$GREEN"
        elif echo "$av_useragent" | grep -qi "bitdefender"; then
            print_result "Antivirus Vendor" "Bitdefender" "$GREEN"
        fi
    fi
    
    # Antivirus update URLs
    echo -e "\n${YELLOW}Antivirus Update Activity:${NC}"
    local av_updates=$(grep -i "update\|definitions\|virus\|malware" "$file" | grep -i "http" | head -10)
    if [[ -n "$av_updates" ]]; then
        echo "$av_updates" | awk '{print $9}' | tr -d '"' | while read url; do
            printf "  ${GREEN}%-70s${NC}\n" "$url"
        done
    fi
    
    # Top domains accessed
    echo -e "\n${YELLOW}Top Domains Accessed Through Proxy:${NC}"
    awk '{print $7}' "$file" | grep -oE "https?://[^/]+" | sed 's|https\?://||' | \
        sort | uniq -c | sort -nr | head -15 | \
    while read count domain; do
        printf "  ${CYAN}%-50s${NC} %s requests\n" "$domain" "$count"
    done
    
    # Response code analysis
    echo -e "\n${YELLOW}Squid Response Codes:${NC}"
    awk '{print $4}' "$file" | sort | uniq -c | sort -nr | \
    while read count code; do
        printf "  ${MAGENTA}%-50s${NC} %s occurrences\n" "$code" "$count"
    done
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    
    # Security event analysis
    local denied_requests=$(awk '{print $4}' "$file" | grep -c "DENIED")
    local tunnel_attempts=$(awk '{print $4}' "$file" | grep -c "CONNECT")
    local cache_misses=$(awk '{print $4}' "$file" | grep -c "MISS")
    local direct_connections=$(awk '{print $4}' "$file" | grep -c "DIRECT")
    
    echo -e "\n${YELLOW}Security Event Summary:${NC}"
    print_result "Denied/Blocked Requests" "${denied_requests:-0}" "$RED"
    print_result "Tunnel/CONNECT Attempts" "${tunnel_attempts:-0}" "$YELLOW"
    print_result "Cache Misses" "${cache_misses:-0}" "$CYAN"
    print_result "Direct Connections" "${direct_connections:-0}" "$CYAN"
    
    # Malicious domain detection
    echo -e "\n${YELLOW}Malicious Domain Analysis:${NC}"
    local malware_domains=$(awk '{print $7}' "$file" | grep -icE "malware|virus|trojan|ransomware|adware")
    local phishing_domains=$(awk '{print $7}' "$file" | grep -icE "verify.*account|suspended.*account|secure.*login")
    local crypto_mining=$(awk '{print $7}' "$file" | grep -icE "coinhive|cryptonight|coin-hive|jsecoin")
    local command_control=$(awk '{print $7}' "$file" | grep -icE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{4,5}")
    
    print_result "Malware Domain Requests" "${malware_domains:-0}" "$RED"
    print_result "Phishing Domain Indicators" "${phishing_domains:-0}" "$RED"
    print_result "Crypto Mining Scripts" "${crypto_mining:-0}" "$RED"
    print_result "C2 Server Connections" "${command_control:-0}" "$RED"
    
    # Data exfiltration analysis
    echo -e "\n${YELLOW}Data Exfiltration Risk Analysis:${NC}"
    local large_uploads=$(awk '$5 > 10000000' "$file" | wc -l)
    local file_upload_services=$(awk '{print $7}' "$file" | grep -icE "dropbox|drive\.google|mega\.nz|wetransfer|sendspace")
    local paste_services=$(awk '{print $7}' "$file" | grep -icE "pastebin|paste|hastebin")
    local cloud_storage=$(awk '{print $7}' "$file" | grep -icE "s3\.amazonaws|azure|storage\.cloud")
    
    print_result "Large Uploads (>10MB)" "${large_uploads:-0}" "$RED"
    print_result "File Upload Services" "${file_upload_services:-0}" "$YELLOW"
    print_result "Paste/Text Services" "${paste_services:-0}" "$YELLOW"
    print_result "Cloud Storage Access" "${cloud_storage:-0}" "$CYAN"
    
    # Proxy abuse detection
    echo -e "\n${YELLOW}Proxy Abuse Detection:${NC}"
    local tor_access=$(awk '{print $7}' "$file" | grep -ic "\.onion")
    local vpn_services=$(awk '{print $7}' "$file" | grep -icE "vpn|proxy|anonymizer|hide")
    local suspicious_ports=$(awk '{print $7}' "$file" | grep -cE ":[0-9]{4,5}" | grep -vE ":80|:443|:8080")
    
    print_result "Dark Web (.onion) Access" "${tor_access:-0}" "$RED"
    print_result "VPN/Anonymizer Services" "${vpn_services:-0}" "$YELLOW"
    print_result "Non-Standard Port Access" "${suspicious_ports:-0}" "$YELLOW"
    
    # Bandwidth analysis
    echo -e "\n${YELLOW}Bandwidth & Usage Analysis:${NC}"
    local total_bandwidth=$(awk '{sum+=$5} END {printf "%.0f", sum/1024/1024}' "$file")
    local avg_request_size=$(awk '{sum+=$5; count++} END {printf "%.0f", sum/count}' "$file")
    local high_bandwidth_ips=$(awk '{ip=$3; bytes[ip]+=$5} END {for (i in bytes) if (bytes[i]>100000000) print i}' "$file" | wc -l)
    
    print_result "Total Bandwidth Used" "${total_bandwidth:-0} MB" "$CYAN"
    print_result "Average Request Size" "${avg_request_size:-0} bytes" "$CYAN"
    print_result "High Bandwidth IPs (>100MB)" "${high_bandwidth_ips:-0}" "$YELLOW"
    
    # Temporal anomalies
    echo -e "\n${YELLOW}Temporal Security Analysis:${NC}"
    local weekend_activity=$(awk '{print $1}' "$file" | while read ts; do date -r "${ts%.*}" +%u 2>/dev/null || true; done | grep -cE "^[67]$" 2>/dev/null || true)
    weekend_activity=${weekend_activity:-0}
    local after_hours=$(awk '{print $1}' "$file" | while read ts; do date -r "${ts%.*}" +%H 2>/dev/null || true; done | awk '$1<6 || $1>20' | wc -l 2>/dev/null || true)
    after_hours=${after_hours:-0}
    
    print_result "Weekend Activity" "${weekend_activity:-0} requests" "$YELLOW"
    print_result "After-Hours Activity" "${after_hours:-0} requests" "$YELLOW"
    
    # Overall risk assessment
    local total_security_score=$((malware_domains * 20 + crypto_mining * 15 + tor_access * 10 + large_uploads * 5 + command_control * 25))
    
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $total_security_score -gt 100 ]]; then
        print_result "Risk Level" "CRITICAL - Active threats detected" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL SECURITY FINDINGS:${NC}"
        echo -e "${RED}     • Malware/C2 communication detected${NC}"
        if [[ ${crypto_mining:-0} -gt 0 ]]; then
            echo -e "${RED}     • Crypto mining activity (${crypto_mining} instances)${NC}"
        fi
        if [[ ${tor_access:-0} -gt 0 ]]; then
            echo -e "${RED}     • Dark web access detected (${tor_access} requests)${NC}"
        fi
        echo -e "${RED}     • Immediate network isolation may be required${NC}"
    elif [[ $total_security_score -gt 30 ]]; then
        print_result "Risk Level" "HIGH - Suspicious proxy usage" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Unusual traffic patterns detected${NC}"
        echo -e "${YELLOW}     • Possible data exfiltration attempts${NC}"
        echo -e "${YELLOW}     • Enhanced monitoring required${NC}"
    elif [[ $total_security_score -gt 10 ]]; then
        print_result "Risk Level" "MEDIUM - Monitor activity" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE ACTIVITY:${NC}"
        echo -e "${CYAN}     • Some concerning patterns${NC}"
        echo -e "${CYAN}     • Continue monitoring${NC}"
    else
        print_result "Risk Level" "LOW - Normal proxy usage" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL OPERATION:${NC}"
        echo -e "${GREEN}     • Legitimate proxy traffic${NC}"
        echo -e "${GREEN}     • No significant threats${NC}"
    fi
    
    # Security recommendations
    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    if [[ ${malware_domains:-0} -gt 0 || ${crypto_mining:-0} -gt 0 ]]; then
        echo -e "${RED}  🛡️  URGENT: Scan all clients for malware/cryptominers${NC}"
    fi
    if [[ ${tor_access:-0} -gt 0 ]]; then
        echo -e "${RED}  🚫 Block .onion domains at proxy level${NC}"
    fi
    if [[ ${large_uploads:-0} -gt 10 ]]; then
        echo -e "${YELLOW}  📤 Investigate large uploads for data exfiltration${NC}"
    fi
    if [[ ${command_control:-0} -gt 0 ]]; then
        echo -e "${RED}  🚨 Possible C2 traffic - isolate affected systems${NC}"
    fi
    if [[ ${file_upload_services:-0} -gt 50 ]]; then
        echo -e "${YELLOW}  📁 High file sharing usage - implement DLP policies${NC}"
    fi
    echo -e "${CYAN}  ✓ Implement SSL inspection for encrypted traffic${NC}"
    echo -e "${CYAN}  ✓ Enable Squid access controls and category filtering${NC}"
    echo -e "${CYAN}  ✓ Integrate with threat intelligence feeds${NC}"
}

# Payments log analysis
analyze_payments() {
    local file="$1"
    print_header "PAYMENT/TRANSACTION LOG ANALYSIS"
    
    # If PayPal SOAP/API style logs are detected, use a specialized parser
    if grep -qE 'PPAPIService:|PPHttpConnection:|PayPalAPI|X-PAYPAL-|<soapenv:Envelope' "$file"; then
        # Basic metrics
        local total_requests=$(grep -cE 'PPAPIService: Request:|<ns:DoDirectPaymentRequest>|<ns:DoDirectPaymentReq>' "$file" 2>/dev/null || echo "0")
        print_result "Total Payment Requests" "${total_requests:-0}"
        
        # Amount analysis
        local amounts=$(grep -oE '<ebl:OrderTotal[^>]*>[0-9]+\.[0-9]+' "$file" | grep -oE '[0-9]+\.[0-9]+' || true)
        if [[ -n "$amounts" ]]; then
            local total=$(echo "$amounts" | awk '{sum+=$1} END {printf "%.2f", sum}')
            local average=$(echo "$amounts" | awk '{sum+=$1; c++} END {printf "%.2f", sum/c}')
            local min=$(echo "$amounts" | sort -n | head -1)
            local max=$(echo "$amounts" | sort -n | tail -1)
            print_result "Total Amount" "$$total" "$GREEN"
            print_result "Average Amount" "$$average" "$CYAN"
            print_result "Min/Max Amount" "$$min - $$max" "$YELLOW"
        else
            print_result "Amount Entries" "0" "$YELLOW"
        fi
        
        # Currencies
        local currencies=$(grep -oE '<ebl:OrderTotal currencyID="[^"]+"' "$file" | cut -d'"' -f2 | sort | uniq -c | sort -nr)
        if [[ -n "$currencies" ]]; then
            echo -e "\n${YELLOW}Currencies:${NC}"
            (echo "$currencies" | head -10 || true) | while read count cur; do
                printf "  ${CYAN}%-50s${NC} %s\n" "$cur" "$count"
            done
        fi
        
        # Payment actions
        local actions=$(grep -oE '<ebl:PaymentAction>[^<]+' "$file" | sed 's/.*>//' | sort | uniq -c | sort -nr)
        if [[ -n "$actions" ]]; then
            echo -e "\n${YELLOW}Payment Actions:${NC}"
            (echo "$actions" | head -10 || true) | while read count action; do
                printf "  ${GREEN}%-50s${NC} %s\n" "$action" "$count"
            done
        fi
        
        # Card types and last-four (masked)
        local cards=$(grep -oE '<ebl:CreditCardType>[^<]+' "$file" | sed 's/.*>//' | sort | uniq -c | sort -nr)
        if [[ -n "$cards" ]]; then
            echo -e "\n${YELLOW}Card Types:${NC}"
            (echo "$cards" | head -10 || true) | while read count type; do
                printf "  ${CYAN}%-50s${NC} %s\n" "$type" "$count"
            done
        fi
        
        local last4=$(grep -oE '<ebl:CreditCardLastFourDigits>[0-9]+' "$file" | grep -oE '[0-9]+' | sort | uniq -c | sort -nr)
        if [[ -n "$last4" ]]; then
            echo -e "\n${YELLOW}Card Last-Four (masked):${NC}"
            (echo "$last4" | head -10 || true) | while read count l4; do
                printf "  ${GREEN}**** **** **** %-36s${NC} %s\n" "$l4" "$count"
            done
        fi
        
        # Device IPs
        local ips=$(grep -oE 'X-PAYPAL-DEVICE-IPADDRESS: [^[:space:]]+' "$file" | awk '{print $2}' | sort | uniq -c | sort -nr)
        if [[ -n "$ips" ]]; then
            echo -e "\n${YELLOW}Device IP Addresses:${NC}"
            (echo "$ips" | head -10 || true) | while read count ip; do
                printf "  ${GREEN}%-50s${NC} %s\n" "$ip" "$count"
            done
        fi
        
        # Shipping states
        local states=$(grep -oE '<ebl:StateOrProvince>[A-Z]{2}<' "$file" | sed 's/.*>//; s/<$//' | sort | uniq -c | sort -nr)
        if [[ -n "$states" ]]; then
            echo -e "\n${YELLOW}Shipping States:${NC}"
            (echo "$states" | head -10 || true) | while read count st; do
                printf "  ${MAGENTA}%-50s${NC} %s purchases\n" "$st" "$count"
            done
        fi
        
        # API acknowledgments (if responses captured)
        local ack=$(grep -oE '<ebl:Ack>[^<]+' "$file" | sed 's/.*>//' | sort | uniq -c | sort -nr)
        if [[ -n "$ack" ]]; then
            echo -e "\n${YELLOW}API Acknowledgments:${NC}"
            (echo "$ack" | head -10 || true) | while read count val; do
                local color="$GREEN"; [[ "$val" != "Success" ]] && color="$RED"
                printf "  ${BOLD}%-50s${NC} %s\n" "$val" "$count"
            done
        fi
        
        # Security notes (avoid printing secrets)
        echo -e "\n${YELLOW}Security Notes:${NC}"
        if grep -qE '<ebl:(Password|Signature)>|<ebl:CVV2>' "$file"; then
            echo -e "${RED}  ⚠️  Sensitive credentials present in logs. Avoid storing secrets in plaintext.${NC}"
        else
            echo -e "${CYAN}  ✓ No obvious secrets found in parsed fields${NC}"
        fi
        
        # SOAP-SPECIFIC CYBERSECURITY ASSESSMENT
        print_header "CYBERSECURITY THREAT ANALYSIS"
        echo -e "\n${YELLOW}Fraud Detection Analysis:${NC}"
        
        # Duplicate request detection
        local duplicate_requests=$(grep -oE '<ns:DoDirectPaymentRequest>|PPAPIService: Request:' "$file" | wc -l | tr -d ' ')
        local unique_correlation_ids=$(grep -oE 'CorrelationID>[^<]+' "$file" | sed 's/.*>//' | sort -u | wc -l | tr -d ' ')
        duplicate_requests=${duplicate_requests:-0}
        unique_correlation_ids=${unique_correlation_ids:-0}
        
        local potential_duplicates=0
        if [[ $duplicate_requests -gt 0 && $unique_correlation_ids -gt 0 ]]; then
            potential_duplicates=$((duplicate_requests - unique_correlation_ids))
            [[ $potential_duplicates -lt 0 ]] && potential_duplicates=0
        fi
        print_result "Potential Duplicate Requests" "${potential_duplicates}" "$RED"
        
        # Amount analysis for fraud
        local soap_amounts=$(grep -oE '<ebl:OrderTotal[^>]*>[0-9]+\.[0-9]+' "$file" | grep -oE '[0-9]+\.[0-9]+')
        local high_value_soap=0
        local suspicious_soap_amounts=0
        local small_soap_transactions=0
        
        if [[ -n "$soap_amounts" ]]; then
            high_value_soap=$(echo "$soap_amounts" | awk '$1>1000' | wc -l | tr -d ' ')
            suspicious_soap_amounts=$(echo "$soap_amounts" | awk '$1==9999 || $1==9999.99 || $1>=10000' | wc -l | tr -d ' ')
            small_soap_transactions=$(echo "$soap_amounts" | awk '$1<5 && $1>0' | wc -l | tr -d ' ')
            high_value_soap=${high_value_soap:-0}
            suspicious_soap_amounts=${suspicious_soap_amounts:-0}
            small_soap_transactions=${small_soap_transactions:-0}
            
            print_result "High-Value Transactions (>\$1000)" "${high_value_soap}" "$YELLOW"
            print_result "Suspicious Amount Patterns" "${suspicious_soap_amounts}" "$RED"
        fi
        
        # Geographic anomaly detection
        echo -e "\n${YELLOW}Geographic Anomaly Detection:${NC}"
        local soap_states=$(grep -oE '<ebl:StateOrProvince>[A-Z]{2}<' "$file" | sed 's/.*>//; s/<$//' | sort)
        if [[ -n "$soap_states" ]]; then
            local soap_state_diversity=$(echo "$soap_states" | sort -u | wc -l | tr -d ' ')
            local soap_rare_states=$(echo "$soap_states" | sort | uniq -c | awk '$1==1' | wc -l | tr -d ' ')
            soap_state_diversity=${soap_state_diversity:-0}
            soap_rare_states=${soap_rare_states:-0}
            
            print_result "Single-Transaction States" "${soap_rare_states}" "$YELLOW"
            print_result "Geographic Diversity" "${soap_state_diversity} states" "$CYAN"
        else
            print_result "Geographic Analysis" "N/A - no state data" "$YELLOW"
        fi
        
        # API failure patterns (could indicate attack)
        echo -e "\n${YELLOW}API Security Analysis:${NC}"
        local failed_acks=$(grep -oE '<ebl:Ack>[^<]+' "$file" | sed 's/.*>//' | grep -v "Success" | wc -l | tr -d ' ')
        local total_acks=$(grep -oE '<ebl:Ack>[^<]+' "$file" | wc -l | tr -d ' ')
        failed_acks=${failed_acks:-0}
        total_acks=${total_acks:-0}
        
        local failure_percentage="0"
        if [[ $total_acks -gt 0 ]]; then
            failure_percentage=$(awk -v fa="$failed_acks" -v ta="$total_acks" 'BEGIN {printf "%.1f", (fa * 100) / ta}')
        fi
        
        print_result "Failed API Requests" "${failed_acks} (${failure_percentage}%)" "$RED"
        
        local high_failure_check=$(awk -v fp="$failure_percentage" 'BEGIN {if (fp > 30) print "yes"; else print "no"}')
        if [[ "$high_failure_check" == "yes" ]]; then
            echo -e "${RED}  ⚠️  High API failure rate (possible attack or misconfiguration)${NC}"
        fi
        
        # Velocity analysis
        echo -e "\n${YELLOW}Temporal Fraud Indicators:${NC}"
        local soap_request_count=$(grep -cE 'PPAPIService: Request:|<ns:DoDirectPaymentRequest>' "$file" 2>/dev/null || echo "0")
        soap_request_count=${soap_request_count:-0}
        
        local soap_velocity="NO - Normal velocity"
        local soap_velocity_color="$GREEN"
        if [[ $soap_request_count -gt 1000 ]]; then
            soap_velocity="YES - Possible batch fraud or attack"
            soap_velocity_color="$RED"
        elif [[ $soap_request_count -gt 500 ]]; then
            soap_velocity="MODERATE - High volume detected"
            soap_velocity_color="$YELLOW"
        fi
        print_result "High Transaction Velocity" "$soap_velocity" "$soap_velocity_color"
        
        # Card testing detection
        echo -e "\n${YELLOW}Card Testing Detection:${NC}"
        local small_soap_percentage="0"
        if [[ $soap_request_count -gt 0 && $small_soap_transactions -gt 0 ]]; then
            small_soap_percentage=$(awk -v st="$small_soap_transactions" -v tr="$soap_request_count" 'BEGIN {printf "%.1f", (st * 100) / tr}')
        fi
        
        print_result "Small Transactions (<\$5)" "${small_soap_transactions} (${small_soap_percentage}%)" "$YELLOW"
        
        local small_soap_check=$(awk -v sp="$small_soap_percentage" 'BEGIN {if (sp > 20) print "yes"; else print "no"}')
        if [[ "$small_soap_check" == "yes" ]]; then
            echo -e "${RED}  ⚠️  High rate of small transactions (card testing indicator)${NC}"
        fi
        
        # Round amount pattern analysis
        echo -e "\n${YELLOW}Amount Pattern Analysis:${NC}"
        if [[ -n "$soap_amounts" ]]; then
            local soap_round_amounts=$(echo "$soap_amounts" | awk '$1 ~ /\.00$/' | wc -l | tr -d ' ')
            soap_round_amounts=${soap_round_amounts:-0}
            
            local soap_round_percentage="0"
            if [[ $soap_request_count -gt 0 ]]; then
                soap_round_percentage=$(awk -v ra="$soap_round_amounts" -v tr="$soap_request_count" 'BEGIN {printf "%.1f", (ra * 100) / tr}')
            fi
            
            print_result "Round Amount Transactions" "${soap_round_amounts} (${soap_round_percentage}%)" "$YELLOW"
            
            local soap_round_check=$(awk -v rp="$soap_round_percentage" 'BEGIN {if (rp > 80) print "yes"; else print "no"}')
            if [[ "$soap_round_check" == "yes" ]]; then
                echo -e "${RED}  ⚠️  High percentage of round amounts (fraud indicator)${NC}"
            fi
            
            # Most common amount clustering
            local most_common_soap_amount=$(echo "$soap_amounts" | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
            local soap_amount_cluster=$(echo "$soap_amounts" | sort | uniq -c | sort -nr | head -1 | awk '{print $1}' | tr -d ' ')
            soap_amount_cluster=${soap_amount_cluster:-0}
            
            print_result "Most Common Amount" "\$${most_common_soap_amount:-N/A} (${soap_amount_cluster} times)" "$CYAN"
            if [[ $soap_amount_cluster -gt 50 ]]; then
                echo -e "${YELLOW}  ⚠️  Suspicious amount clustering detected${NC}"
            fi
        fi
        
        # IP-based anomalies
        echo -e "\n${YELLOW}Network Security Analysis:${NC}"
        local soap_unique_ips=$(grep -oE 'X-PAYPAL-DEVICE-IPADDRESS: [^[:space:]]+' "$file" | awk '{print $2}' | sort -u | wc -l | tr -d ' ')
        soap_unique_ips=${soap_unique_ips:-0}
        
        if [[ $soap_unique_ips -gt 0 ]]; then
            print_result "Unique Device IPs" "${soap_unique_ips}" "$CYAN"
            
            # Check for excessive IPs (could indicate distributed attack)
            if [[ $soap_unique_ips -gt 100 ]]; then
                echo -e "${RED}  ⚠️  High IP diversity (possible distributed fraud attack)${NC}"
            fi
        else
            print_result "Device IP Analysis" "N/A - no IP data captured" "$YELLOW"
        fi
        
        # Calculate overall fraud score for SOAP
        local soap_card_testing_score=0
        [[ "$small_soap_check" == "yes" ]] && soap_card_testing_score=30
        
        local soap_round_score=0
        [[ "${soap_round_check:-no}" == "yes" ]] && soap_round_score=15
        
        local soap_velocity_score=0
        [[ $soap_request_count -gt 1000 ]] && soap_velocity_score=20
        
        local soap_failure_score=0
        [[ "$high_failure_check" == "yes" ]] && soap_failure_score=25
        
        local soap_fraud_score=$((potential_duplicates * 20 + suspicious_soap_amounts * 10 + soap_card_testing_score + soap_round_score + soap_velocity_score + soap_failure_score))
        
        echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
        if [[ $soap_fraud_score -gt 60 ]]; then
            print_result "Fraud Risk Level" "CRITICAL - High fraud indicators" "$RED"
            echo -e "\n${RED}  ⚠️  CRITICAL FRAUD INDICATORS:${NC}"
            echo -e "${RED}     • Multiple fraud patterns detected in SOAP traffic${NC}"
            [[ ${potential_duplicates:-0} -gt 0 ]] && echo -e "${RED}     • Duplicate request attempts (${potential_duplicates})${NC}"
            [[ ${suspicious_soap_amounts:-0} -gt 0 ]] && echo -e "${RED}     • Suspicious amount patterns (${suspicious_soap_amounts})${NC}"
            [[ "$high_failure_check" == "yes" ]] && echo -e "${RED}     • High API failure rate detected${NC}"
            echo -e "${RED}     • Immediate fraud investigation required${NC}"
        elif [[ $soap_fraud_score -gt 30 ]]; then
            print_result "Fraud Risk Level" "HIGH - Suspicious patterns detected" "$RED"
            echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
            echo -e "${YELLOW}     • Concerning API transaction patterns${NC}"
            echo -e "${YELLOW}     • Enhanced fraud monitoring needed${NC}"
        elif [[ $soap_fraud_score -gt 10 ]]; then
            print_result "Fraud Risk Level" "MEDIUM - Minor anomalies" "$YELLOW"
            echo -e "\n${CYAN}  ✓ MODERATE RISK:${NC}"
            echo -e "${CYAN}     • Some anomalies in API requests${NC}"
            echo -e "${CYAN}     • Standard fraud controls adequate${NC}"
        else
            print_result "Fraud Risk Level" "LOW - Normal API traffic" "$GREEN"
            echo -e "\n${GREEN}  ✅ NORMAL TRANSACTION PROFILE:${NC}"
            echo -e "${GREEN}     • No significant fraud indicators${NC}"
            echo -e "${GREEN}     • API requests appear legitimate${NC}"
        fi
        
        echo -e "\n${YELLOW}Security & Fraud Prevention Recommendations:${NC}"
        if [[ ${potential_duplicates:-0} -gt 0 ]]; then
            echo -e "${RED}  🔍 URGENT: Investigate duplicate API requests${NC}"
        fi
        if [[ ${suspicious_soap_amounts:-0} -gt 5 ]]; then
            echo -e "${RED}  💰 Review high-value and threshold-skirting payments${NC}"
        fi
        if [[ "${small_soap_check:-no}" == "yes" ]]; then
            echo -e "${RED}  🎯 Possible card testing - implement API velocity checks${NC}"
        fi
        if [[ "${soap_round_check:-no}" == "yes" ]]; then
            echo -e "${YELLOW}  📊 High round-amount ratio - review for scripted attacks${NC}"
        fi
        if [[ "$high_failure_check" == "yes" ]]; then
            echo -e "${RED}  🚨 High failure rate - possible brute force or enumeration${NC}"
        fi
        if grep -qE '<ebl:(Password|Signature)>|<ebl:CVV2>' "$file"; then
            echo -e "${RED}  🔐 CRITICAL: Remove sensitive credentials from logs immediately${NC}"
        fi
        echo -e "${CYAN}  ✓ Implement API request throttling and rate limiting${NC}"
        echo -e "${CYAN}  ✓ Deploy correlation ID tracking for duplicate detection${NC}"
        echo -e "${CYAN}  ✓ Enable IP-based geolocation fraud scoring${NC}"
        echo -e "${CYAN}  ✓ Implement real-time anomaly detection for API patterns${NC}"
        echo -e "${CYAN}  ✓ Sanitize logs to exclude PII and payment credentials${NC}"
        
        return
    fi
    
    # Otherwise, assume CSV/TSV format (txn_id,amount,state,...)
    # Detect delimiter (comma or tab)
    local delimiter="," 
    if head -1 "$file" | grep -q $'\t'; then
        delimiter=$'\t'
    fi
    
    # Basic metrics
    local total_transactions=$(grep -v '^#\|^$' "$file" | tail -n +2 | wc -l | tr -d ' ')
    total_transactions=${total_transactions:-0}
    print_result "Total Transactions" "$total_transactions"
    
    # Transaction analysis
    echo -e "\n${YELLOW}Transaction Analysis:${NC}"
    
    if grep -q "[0-9]\+\.[0-9]\+" "$file"; then
        echo -e "\n${CYAN}Largest Transactions:${NC}"
        (tail -n +2 "$file" | sort -t"$delimiter" -k2 -nr 2>/dev/null | head -10 || true) | while IFS="$delimiter" read -r txn amount rest; do
            [[ -n "$txn" && -n "$amount" ]] && printf "  ${GREEN}%-50s${NC} $%s\n" "$txn" "$amount"
        done
        
        local largest_txn=$(tail -n +2 "$file" | sort -t"$delimiter" -k2 -nr 2>/dev/null | head -1 | cut -d"$delimiter" -f1)
        local largest_amount=$(tail -n +2 "$file" | sort -t"$delimiter" -k2 -nr 2>/dev/null | head -1 | cut -d"$delimiter" -f2)
        if [[ -n "$largest_txn" ]]; then
            echo
            print_result "Largest Transaction ID" "$largest_txn" "$GREEN"
            print_result "Transaction Amount" "\$${largest_amount}" "$GREEN"
        fi
    fi
    
    # State/location analysis
    echo -e "\n${YELLOW}Geographic Analysis:${NC}"
    for col in 3 4 5; do
        local state_data=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | head -1)
        if [[ -n "$state_data" ]]; then
            echo -e "${CYAN}Purchases by State:${NC}"
            (tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | sort | uniq -c | sort -nr | head -15 || true) | while read count state; do
                printf "  ${MAGENTA}%-50s${NC} %s purchases\n" "$state" "$count"
            done
            local top_state=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
            local top_state_count=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | sort | uniq -c | sort -nr | head -1 | awk '{print $1}')
            echo
            print_result "Top Purchasing State" "$top_state ($top_state_count purchases)" "$GREEN"
            break
        fi
    done
    
    # Amount statistics
    echo -e "\n${YELLOW}Payment Statistics:${NC}"
    for col in 2 3 4; do
        local amounts=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[0-9]+\.[0-9]+$')
        if [[ -n "$amounts" ]]; then
            local total=$(echo "$amounts" | awk '{sum+=$1} END {printf "%.2f", sum}')
            local average=$(echo "$amounts" | awk '{sum+=$1; count++} END {printf "%.2f", sum/count}')
            local min=$(echo "$amounts" | sort -n | head -1)
            local max=$(echo "$amounts" | sort -n | tail -1)
            print_result "Total Revenue" "\$${total}" "$GREEN"
            print_result "Average Transaction" "\$${average}" "$CYAN"
            print_result "Minimum Purchase" "\$${min}" "$YELLOW"
            print_result "Maximum Purchase" "\$${max}" "$GREEN"
            break
        fi
    done
    
    # Transaction ID patterns
    echo -e "\n${YELLOW}Transaction ID Analysis:${NC}"
    local txn_pattern=$(tail -n +2 "$file" | cut -d"$delimiter" -f1 | head -1)
    print_result "Transaction ID Format Example" "$txn_pattern" "$CYAN"
    
    # COMPREHENSIVE CYBERSECURITY ASSESSMENT
    print_header "CYBERSECURITY THREAT ANALYSIS"
    echo -e "\n${YELLOW}Fraud Detection Analysis:${NC}"
    local duplicate_txns=$(tail -n +2 "$file" | cut -d"$delimiter" -f1 | sort | uniq -d | wc -l | tr -d ' ')
    duplicate_txns=${duplicate_txns:-0}
    print_result "Duplicate Transaction IDs" "${duplicate_txns}" "$RED"
    
    local high_value_count=0
    local suspicious_amounts=0
    if grep -q "[0-9]\+\.[0-9]\+" "$file"; then
        high_value_count=$(tail -n +2 "$file" | awk -F"$delimiter" '$2>1000' | wc -l | tr -d ' ')
        high_value_count=${high_value_count:-0}
        suspicious_amounts=$(tail -n +2 "$file" | awk -F"$delimiter" '$2==9999 || $2==9999.99 || $2>=10000' | wc -l | tr -d ' ')
        suspicious_amounts=${suspicious_amounts:-0}
        print_result "High-Value Transactions (>\$1000)" "${high_value_count}" "$YELLOW"
        print_result "Suspicious Amount Patterns" "${suspicious_amounts}" "$RED"
    fi
    
    echo -e "\n${YELLOW}Geographic Anomaly Detection:${NC}"
    for col in 3 4 5; do
        local state_data=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | head -1)
        if [[ -n "$state_data" ]]; then
            local rare_states=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | sort | uniq -c | awk '$1==1' | wc -l)
            local state_diversity=$(tail -n +2 "$file" | cut -d"$delimiter" -f$col | grep -E '^[A-Z]{2}$' | sort -u | wc -l)
            print_result "Single-Transaction States" "${rare_states:-0}" "$YELLOW"
            print_result "Geographic Diversity" "${state_diversity:-0} states" "$CYAN"
            break
        fi
    done
    
    echo -e "\n${YELLOW}Temporal Fraud Indicators:${NC}"
    local has_timestamps=$(head -1 "$file" | grep -ic "time\|date")
    if [[ $has_timestamps -gt 0 ]]; then
        print_result "Timestamp Column Detected" "Yes - temporal analysis possible" "$GREEN"
    else
        print_result "Timestamp Analysis" "N/A - no timestamp column" "$YELLOW"
    fi
    
    local txn_per_entity=$(tail -n +2 "$file" | wc -l)
    if [[ $txn_per_entity -gt 1000 ]]; then
        local high_velocity="YES - Possible batch fraud"
        local velocity_color="$RED"
    else
        local high_velocity="NO - Normal velocity"
        local velocity_color="$GREEN"
    fi
    print_result "High Transaction Velocity" "$high_velocity" "$velocity_color"
    
    echo -e "\n${YELLOW}Amount Pattern Analysis:${NC}"
    if grep -q "[0-9]\+\.[0-9]\+" "$file"; then
        local round_amounts=$(tail -n +2 "$file" | awk -F"$delimiter" '$2 ~ /\.00$/' | wc -l | tr -d ' ')
        round_amounts=${round_amounts:-0}
        
        local round_percentage="0"
        if [[ $total_transactions -gt 0 ]]; then
            round_percentage=$(awk -v ra="$round_amounts" -v tt="$total_transactions" 'BEGIN {printf "%.1f", (ra * 100) / tt}')
        fi
        
        print_result "Round Amount Transactions" "$round_amounts (${round_percentage}%)" "$YELLOW"
        
        local round_pct_check=$(awk -v rp="$round_percentage" 'BEGIN {if (rp > 80) print "yes"; else print "no"}')
        if [[ "$round_pct_check" == "yes" ]]; then
            echo -e "${RED}  ⚠️  High percentage of round amounts (fraud indicator)${NC}"
        fi
        
        local most_common_amount=$(tail -n +2 "$file" | awk -F"$delimiter" '{print $2}' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
        local amount_cluster_count=$(tail -n +2 "$file" | awk -F"$delimiter" '{print $2}' | sort | uniq -c | sort -nr | head -1 | awk '{print $1}' | tr -d ' ')
        amount_cluster_count=${amount_cluster_count:-0}
        print_result "Most Common Amount" "\$${most_common_amount:-N/A} (${amount_cluster_count} times)" "$CYAN"
        if [[ $amount_cluster_count -gt 50 ]]; then
            echo -e "${YELLOW}  ⚠️  Suspicious amount clustering detected${NC}"
        fi
    fi
    
    echo -e "\n${YELLOW}Card Testing Detection:${NC}"
    local small_transactions=$(tail -n +2 "$file" | awk -F"$delimiter" '$2<5 && $2>0' | wc -l 2>/dev/null | tr -d ' ')
    small_transactions=${small_transactions:-0}
    
    local small_txn_percentage="0"
    if [[ $total_transactions -gt 0 ]]; then
        small_txn_percentage=$(awk -v st="$small_transactions" -v tt="$total_transactions" 'BEGIN {printf "%.1f", (st * 100) / tt}')
    fi
    
    print_result "Small Transactions (<\$5)" "$small_transactions (${small_txn_percentage}%)" "$YELLOW"
    
    local small_txn_check=$(awk -v sp="$small_txn_percentage" 'BEGIN {if (sp > 20) print "yes"; else print "no"}')
    if [[ "$small_txn_check" == "yes" ]]; then
        echo -e "${RED}  ⚠️  High rate of small transactions (card testing indicator)${NC}"
    fi
    
    # Calculate fraud score
    local card_testing_score=0
    if [[ "$small_txn_check" == "yes" ]]; then
        card_testing_score=30
    fi
    local fraud_score=$((duplicate_txns * 20 + suspicious_amounts * 10 + card_testing_score))
    echo -e "\n${YELLOW}Overall Risk Assessment:${NC}"
    if [[ $fraud_score -gt 50 ]]; then
        print_result "Fraud Risk Level" "CRITICAL - High fraud indicators" "$RED"
        echo -e "\n${RED}  ⚠️  CRITICAL FRAUD INDICATORS:${NC}"
        echo -e "${RED}     • Multiple fraud patterns detected${NC}"
        if [[ ${duplicate_txns:-0} -gt 0 ]]; then
            echo -e "${RED}     • Duplicate transaction IDs found (${duplicate_txns})${NC}"
        fi
        if [[ ${suspicious_amounts:-0} -gt 0 ]]; then
            echo -e "${RED}     • Suspicious amount patterns (${suspicious_amounts})${NC}"
        fi
        echo -e "${RED}     • Immediate fraud investigation required${NC}"
    elif [[ $fraud_score -gt 20 ]]; then
        print_result "Fraud Risk Level" "HIGH - Suspicious patterns detected" "$RED"
        echo -e "\n${YELLOW}  📊 HIGH RISK INDICATORS:${NC}"
        echo -e "${YELLOW}     • Some concerning transaction patterns${NC}"
        echo -e "${YELLOW}     • Enhanced fraud monitoring needed${NC}"
    elif [[ $fraud_score -gt 5 ]]; then
        print_result "Fraud Risk Level" "MEDIUM - Minor anomalies" "$YELLOW"
        echo -e "\n${CYAN}  ✓ MODERATE RISK:${NC}"
        echo -e "${CYAN}     • Some anomalies detected${NC}"
        echo -e "${CYAN}     • Standard fraud controls adequate${NC}"
    else
        print_result "Fraud Risk Level" "LOW - Normal transactions" "$GREEN"
        echo -e "\n${GREEN}  ✅ NORMAL TRANSACTION PROFILE:${NC}"
        echo -e "${GREEN}     • No significant fraud indicators${NC}"
        echo -e "${GREEN}     • Transactions appear legitimate${NC}"
    fi
    
    echo -e "\n${YELLOW}Security & Fraud Prevention Recommendations:${NC}"
    if [[ ${duplicate_txns:-0} -gt 0 ]]; then
        echo -e "${RED}  🔍 URGENT: Investigate duplicate transaction IDs${NC}"
    fi
    if [[ ${suspicious_amounts:-0} -gt 5 ]]; then
        echo -e "${RED}  💰 Review high-value and threshold-skirting transactions${NC}"
    fi
    if [[ "${small_txn_check:-no}" == "yes" ]]; then
        echo -e "${RED}  🎯 Possible card testing - implement velocity checks${NC}"
    fi
    if [[ "${round_pct_check:-no}" == "yes" ]]; then
        echo -e "${YELLOW}  📊 High round-amount ratio - review for anomalies${NC}"
    fi
    echo -e "${CYAN}  ✓ Implement real-time fraud scoring${NC}"
    echo -e "${CYAN}  ✓ Enable geographic velocity checks${NC}"
    echo -e "${CYAN}  ✓ Deploy machine learning fraud detection${NC}"
    echo -e "${CYAN}  ✓ Maintain transaction deduplication controls${NC}"
}

# Entrypoint (moved to end so all functions are defined before use)
case "${1:-}" in
    start|--start)
        handle_start
        exit $?
        ;;
    -h|--help|help)
        print_usage
        exit 0
        ;;
esac

# Direct invocation
LOG="${1:-}"
CONFIG="${2:-auto}"

if [[ -z "$LOG" ]]; then
    echo -e "${RED}Error: No arguments provided.${NC}"
    echo
    print_usage
    exit 1
fi

if [[ ! -f "$LOG" ]]; then
    echo -e "${RED}Error: Log file '${LOG}' not found.${NC}"
    exit 1
fi

run_analysis "$LOG" "$CONFIG"

