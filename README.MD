
### 🏫 İSTİNYE ÜNİVERSİTESİ - MESLEK YÜKSEKOKULU
**Program:** Bilişim Güvenliği Teknolojisi  
**Ders:** Sızma Testi (Penetrasyon)  
**Öğrenci:** Muhammet Eren Çapan  
**Proje Tarihi:** Mart - Nisan 2026


<div align="center">
  <h1>🛡️ Aegis-SSH Auditing Suite v5.0 (Pro)</h1>
  <p>Kurumsal ağlarda ve dışa açık sunucularda zayıf SSH yapılandırmalarını tespit etmek için geliştirilmiş yüksek performanslı Asenkron Sızma Testi ve Güvenlik Denetim (Auditing) Aracı.</p>

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)
![AsyncIO](https://img.shields.io/badge/framework-asyncio-white.svg)
</div>

## 📖 İçindekiler
* [✨ Temel Özellikler](#-temel-özellikler)
* [🛠️ Mimari Yapı ve Karşılaştırma](#️-mimari-yapı-ve-karşılaştırma)
* [🎯 İncelenen Zafiyet: Brute-Force](#-incelenen-zafiyet-zayıf-ssh-yapılandırması-ve-brute-force)
* [🛡️ Zafiyet Çözümü ve Savunma](#️-zafiyet-çözümü-ve-savunma-stratejileri)
* [🚀 Kurulum](#-kurulum)
* [📋 Kullanım Rehberi](#-kullanım)
* [⚠️ Yasal Uyarı](#️-yasal-uyarı)

## ✨ Temel Özellikler

- ⚡ **Asenkron İletişim:** Python'un `asyncio` kütüphanesi ve `Semaphore` mekanizması sayesinde sistem kaynaklarını tüketmeden aynı anda onlarca bağlantı açabilir.
- 🌐 **Alt Ağ (Subnet) ve DNS Taraması:** Sadece tek bir IP adresini değil, alan adlarını (Örn: `firma.com`) ve koca bir alt ağı (Örn: `192.168.1.0/24`) otomatik çözümleyerek açık SSH portlarını saniyeler içinde tarar.
- 🥷 **Gelişmiş Evasion (Kaçınma) Modu:** Güvenlik duvarı (WAF/IPS) ve Fail2Ban sistemlerini atlatabilmek için dinamik *Jitter* (Zamanlama manipülasyonu), SSH *Client Fingerprint Spoofing* (İstemci sahteciliği) ve rastgele şifre deseni uygulama özellikleriyle donatılmıştır.
- 💾 **Kayıp Önleyici Oturum Yönetimi:** Süreç otomatik olarak `session.json` dosyasına kaydedilir. Yeniden başlatıldığında kaldığı yerden devam eder.
- 💬 **Discord Webhook Entegrasyonu:** Tarama sonuçları anlık olarak belirtilen Discord kanalına şık bir "Embed" olarak düşer.
- 📊 **Dinamik HTML Raporlama:** Her IP adresi için keşfedilen Banner, zafiyet durumu ve kırılan şifreleri içeren `.html` raporu otomatik olarak oluşturulur.

## 🛠️ Mimari Yapı ve Karşılaştırma

Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde **"Event Loop"** mimarisiyle yönetir. Tıpkı Rust dilindeki `tokio::sync::Semaphore` yapısına benzer bir şekilde `asyncio.Semaphore` kullanılarak, hedefin kapasitesine göre eşzamanlı limitler (Rate-limiting) konulur. Bu mimari sayesinde klasik çoklu-iş parçacıklı (Multi-threaded) scriptlerdeki "Socket Exhaustion" işletim sistemi kilitlenmeleri önlenir.

## 🎯 İncelenen Zafiyet: Zayıf SSH Yapılandırması ve Brute-Force

Bu projede, sunucularda en sık karşılaşılan **zayıf parola politikaları** ve **korumasız SSH servisi** zafiyetleri incelenmiştir. Sistem yöneticilerinin varsayılan ayarları değiştirmemesi veya zayıf şifreler kullanması, saldırganların kaba kuvvet (brute-force) yöntemleriyle sistemde yetkisiz "root" erişimi sağlamasına yol açmaktadır. Aegis-SSH, kurumsal ağlardaki bu yapılandırma hatalarını tespit etmek için tasarlanmıştır.

## 🛡️ Zafiyet Çözümü ve Savunma Stratejileri

Tespit edilen bu zafiyetleri önlemek için aşağıdaki savunma mekanizmaları uygulanmalıdır:

1. **Anahtar Tabanlı Doğrulama (Key-Based Auth):** Parola ile giriş tamamen devre dışı bırakılmalıdır (`PasswordAuthentication no`).
2. **Fail2Ban Entegrasyonu:** Belirli sayıda hatalı deneme yapan IP adresleri dinamik olarak bloklanmalıdır.
3. **Port Knocking:** SSH portu varsayılan "22" yerine değiştirilmeli ve sadece yetkili IP'lere erişim izni verilmelidir.

## 🚀 Kurulum

Sisteminizde Python 3.8+ kurulu olmalıdır.

```bash
# Depoyu klonlayın
git clone [https://github.com/Winslowe/Aegis-SSH.git](https://github.com/Winslowe/Aegis-SSH.git)
cd Aegis-SSH

# Gerekli bağımlılıkları yükleyin
pip install -r requirements.txt

# Aracı çalıştırın
python src/main.py
