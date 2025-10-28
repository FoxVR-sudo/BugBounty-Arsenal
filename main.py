import os
from scope_parser import parse_scope
from scanner import run_scan
from report_generator import generate_html_report

def main():
    print("=== Safe Bug Bounty Scanner ===")

    # Въвеждане на CSV файл със scope
    csv_file = input("📁 Въведи CSV файл със scope (URL,Status): ").strip()
    if not os.path.exists(csv_file):
        print(f"[!] Файлът '{csv_file}' не съществува.")
        return

    try:
        in_scope, out_scope = parse_scope(csv_file)
        print(f"[+] In-scope цели: {len(in_scope)} | Out-of-scope: {len(out_scope)}")
    except Exception as e:
        print(f"[!] Грешка при парсване на scope файла: {e}")
        return

    # Потвърждение за стартиране
    start = input("🚀 Стартираме ли сканирането на in-scope URL? (y/n): ").strip().lower()
    if start != "y":
        print("⏹ Сканирането е отказано.")
        return

    # Стартиране на сканиране
    try:
        print(f"[+] Стартира се сканиране на {len(in_scope)} URL...")
        results = run_scan(in_scope)
    except Exception as e:
        print(f"[!] Грешка при стартиране на сканиране: {e}")
        results = []

    # Генериране на репорт
    try:
        os.makedirs("reports", exist_ok=True)
        output_path = os.path.join("reports", "report.html")
        generate_html_report(results, output_path)
        print(f"✅ Готово! Репортът е записан в: {output_path}")
    except Exception as e:
        print(f"[!] Грешка при запис на репорт: {e}")

if __name__ == "__main__":
    main()
