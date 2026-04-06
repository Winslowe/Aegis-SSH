<div align="center">
  <h1>🛡️ Aegis-SSH Auditing Suite v5.0 (Pro)</h1>
  <p>Kurumsal ağlarda ve dışa açık sunucularda zayıf SSH yapılandırmalarını tespit etmek için geliştirilmiş yüksek performanslı Asenkron Sızma Testi ve Güvenlik Denetim (Auditing) Aracı.</p>
</div>

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)
![AsyncIO](https://img.shields.io/badge/framework-asyncio-white.svg)

## ✨ Temel Özellikler

- ⚡ **Asenkron İletişim:** Python'un `asyncio` kütüphanesi ve `Semaphore` mekanizması sayesinde sistem kaynaklarını tüketmeden aynı anda onlarca bağlantı açabilir.
- 🌐 **Alt Ağ (Subnet) ve DNS Taraması:** Sadece tek bir IP adresini değil, alan adlarını (Örn: `firma.com`) ve koca bir alt ağı (Örn: `192.168.1.0/24`) otomatik çözümleyerek açık SSH portlarını saniyeler içinde tarar.
- 🥷 **Gelişmiş Evasion (Kaçınma) Modu:** Güvenlik duvarı (WAF/IPS) ve Fail2Ban sistemlerini atlatabilmek için dinamik *Jitter* (Zamanlama manipülasyonu), SSH *Client Fingerprint Spoofing* (İstemci sahteciliği) ve rastgele şifre deseni uygulama özellikleriyle donatılmıştır.
- 💾 **Kayıp Önleyici Oturum Yönetimi (Session Resume):** Tarama sırasında oluşabilecek kesintilerde veya isteğe bağlı durdurmalarda, süreç otomatik olarak `session.json` dosyasına kaydedilir. Yeniden başlatıldığında kaldığı ağ ve şifre indeksinden kaldığı yerden devam eder.
- 💬 **Discord Webhook Entegrasyonu:** Uzun süren taramaların sonucu, ağda birden fazla cihaz taranırken anlık olarak belirtilen Discord kanalına şık bir "Embed" olarak düşer.
- 📊 **Dinamik HTML Raporlama:** Tüm ağ taraması bittiğinde, her IP adresi ve cihaz için keşfedilen Banner, zafiyet durumu ve kırılan şifreleri içeren son derece okunaklı bir `.html` raporu otomatik olarak kaydedilir.
- 🔍 **Banner Grabbing & Versiyon Tespiti:** Kaba kuvvet (Brute-force) işleminden önce hedef porttaki SSH versiyonunu okuyarak, eski ve bilinen zafiyetleri olan sürümlerin analiz edilmesine olanak tanır.
- 🔒 **Sessiz ve Kararlı:** Geleneksel threading yapılarının aksine "Connection Refused" veya timeout hatalarını zarifçe tolere eder. `asyncssh` kütüphanesinin public key (StrictHostKeyChecking) doğrulama aşamalarını atlayarak hız kazanır.

## 🛠️ Mimari Yapı ve Karşılaştırma

Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde "Event Loop" mimarisiyle yönetir. Tıpkı Rust dilindeki `tokio::sync::Semaphore` yapısına benzer bir şekilde `asyncio.Semaphore` kullanılarak, hedefin kapasitesine göre eşzamanlı limitler (Rate-limiting) konulur. Bu mimari sayesinde klasik çoklu-iş parçacıklı (Multi-threaded) scriptlerdeki "Socket Exhaustion" işletim sistemi kilitlenmeleri önlenir. Arka planda SSH yetki kanalları paralelleştirilir.

## 🎯 İncelenen Zafiyet: Zayıf SSH Yapılandırması ve Brute-Force

Bu projede, sunucularda en sık karşılaşılan **zayıf parola politikaları** ve **korumasız SSH servisi** zafiyetleri incelenmiştir. Sistem yöneticilerinin varsayılan ayarları değiştirmemesi veya zayıf şifreler kullanması, saldırganların kaba kuvvet (brute-force) yöntemleriyle sistemde yetkisiz "root" erişimi sağlamasına yol açmaktadır. Aegis-SSH, kurumsal ağlardaki bu yapılandırma hatalarını tespit etmek ve görünür kılmak için tasarlanmıştır.

## 🛡️ Zafiyet Çözümü ve Savunma Stratejileri

Aegis-SSH gibi araçların başarılı olmasını engellemek ve tespit edilen zafiyetleri çözmek için aşağıdaki güvenlik adımları uygulanmalıdır:

- **Anahtar Tabanlı Doğrulama (Key-Based Authentication):** SSH yapılandırmasında parola ile giriş tamamen devre dışı bırakılmalı (`PasswordAuthentication no`), bunun yerine kriptografik anahtarlar (Ed25519 / RSA) kullanılmalıdır.
- **Dinamik Engelleme (Fail2Ban/DenyHosts):** Art arda yapılan başarısız giriş denemeleri tespit edilerek IP adresi güvenlik duvarı seviyesinde otomatik olarak engellenmelidir.
- **Port Değiştirme ve Port Knocking:** Varsayılan "22" portu değiştirilmeli veya servise erişim sadece belirli bir IP havuzu ile sınırlandırılmalıdır.

## 🚀 Kurulum

Sisteminizde Python 3.8 veya üzeri bir sürüm kurulu olmalıdır. Klonlama ve ortamı hazırlama adımları:

```bash
# Depoyu klonlayın
git clone [https://github.com/KullaniciAdiniz/Aegis-SSH.git](https://github.com/KullaniciAdiniz/Aegis-SSH.git)
cd Aegis-SSH

# Gerekli bağımlılıkları yükleyin
pip install -r requirements.txt

# Aracı çalıştırın
python main.py
