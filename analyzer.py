import re
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# Паттерны атак для поиска в URL
ATTACK_PATTERNS = {
    "SQL-инъекция": [r"UNION", r"SELECT", r"OR\s+1=1", r"INSERT", r"DROP"],
    "XSS (Cross-Site Scripting)": [r"<script>", r"alert\(", r"javascript:"],
    "LFI / Path Traversal": [r"etc/passwd", r"\.\./", r"boot\.ini"]
}

def analyze_logs(file_path):
    failed_logins = defaultdict(int)
    detected_attacks = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(Fore.RED + f"[!] Ошибка: Файл {file_path} не найден!")
        return

    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + f"[*] АНАЛИЗ ЛОГ-ФАЙЛА: {file_path}")
    print(Fore.CYAN + f"[*] Всего обработано строк: {len(lines)}")
    print(Fore.CYAN + "=" * 60 + "\n")

    for line in lines:
        # Извлекаем IP-адрес
        ip_match = re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if not ip_match:
            continue
        ip = ip_match.group(1)

        # 1. Поиск подозрительных веб-атак в строке
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    detected_attacks.append((ip, attack_type, line.strip()))
                    break

        # 2. Подсчет неудачных попыток входа (код 401)
        if " 401 " in line:
            failed_logins[ip] += 1

    # ВЫВОД РЕЗУЛЬТАТОВ

    # Отчет по аномальным атакам
    print(Fore.YELLOW + "=== ОБНАРУЖЕННЫЕ ВЕБ-АТАКИ ===")
    if detected_attacks:
        for ip, attack_type, raw_line in detected_attacks:
            print(Fore.RED + f"[!] {ip} -> {attack_type}")
    else:
        print(Fore.GREEN + "[+] Подозрений на инъекции и XSS не обнаружено.")

    print("\n" + Fore.YELLOW + "=== ПОДОЗРЕНИЯ НА BRUTE-FORCE (Попытки подбора) ===")
    brute_found = False
    for ip, count in failed_logins.items():
        if count >= 5: # Порог подбора
            print(Fore.RED + f"[!] ВНИМАНИЕ: IP {ip} совершил {count} неудачных попыток входа!")
            brute_found = True
        elif count > 0:
            print(Fore.GREEN + f"[-] IP {ip}: {count} неудачных попыток (в пределах нормы).")

    if not brute_found and not failed_logins:
        print(Fore.GREEN + "[+] Подозрений на Brute-force не обнаружено.")

    print("\n" + Fore.CYAN + "=" * 60)

if __name__ == "__main__":
    analyze_logs("access.log")