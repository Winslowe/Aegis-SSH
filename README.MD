**Proje Adı:** Aegis-SSH Auditing Suite  

---

<div align="center">
  <h1>🛡️ Aegis-SSH Auditing Suite v5.0 (Pro)</h1>
  <p>Kurumsal ağlarda ve dışa açık sunucularda zayıf SSH yapılandırmalarını tespit etmek için geliştirilmiş yüksek performanslı Asenkron Sızma Testi ve Güvenlik Denetim (Auditing) Aracı.</p>

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![AsyncIO](https://img.shields.io/badge/framework-asyncio-white.svg)
</div>

## 📖 İçindekiler
* [✨ Temel Özellikler](#-temel-özellikler)
* [🛠️ Mimari Analiz ve Derinlik](#️-mimari-analiz-ve-derinlik)
* [🎯 İncelenen Zafiyet: SSH Brute-Force](#-incelenen-zafiyet-zayıf-ssh-yapılandırması-ve-brute-force)
* [🛡️ Zafiyet Çözümü ve Savunma](#️-zafiyet-çözümü-ve-savunma-stratejileri)
* [🔮 Üretim ve Gelecek Vizyonu](#-üretim-ve-gelecek-vizyonu)
* [🚀 Kurulum ve Çalıştırma](#-kurulum)
* [💬 Discord Webhook](#-discord-webhook-entegrasyonu)
* [⚠️ Yasal Uyarı](#️-yasal-uyarı)

---

## ✨ Temel Özellikler

- ⚡ **Asenkron İletişim:** `asyncio` ve `Semaphore` mekanizması ile sistem kaynaklarını tüketmeden eşzamanlı onlarca bağlantı yönetimi.
- 🌐 **Geniş Ağ Desteği:** Tek IP, Domain veya `192.168.1.0/24` gibi Subnet tarama kabiliyeti.
- 🥷 **Gelişmiş Evasion:** IDS/IPS sistemlerini atlatmak için dinamik *Jitter* ve *Client Fingerprint Spoofing*.
- 📊 **HTML Raporlama:** Her tarama sonunda zafiyet durumunu belgeleyen otomatik `.html` raporu.
- 💾 **Session Resume:** Kesintiye uğrayan taramaları `session.json` üzerinden kaldığı yerden sürdürme.

## 🛠️ Mimari Analiz ve Derinlik

### Neden Bu Yaklaşımı Seçtik?
Klasik çoklu iş parçacıklı (Multi-threaded) scriptlerin aksine Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde **"Event Loop"** mimarisiyle yönetir. 
* **Verimlilik:** Threading yapısı socket exhaustion (soket tükenmesi) hatalarına yol açarken, `asyncio.Semaphore` kullanımıyla rate-limiting uygulanarak hedefin kapasitesine göre güvenli bir tarama yapılır.
* **Performans:** Tek bir işlemci çekirdeği ile binlerce asenkron görevi (task) paralel gibi yürüterek donanım maliyetini minimize eder.

## 🎯 İncelenen Zafiyet: Zayıf SSH Yapılandırması ve Brute-Force

Bu projede, kurumsal sunucularda en sık rastlanan **zayıf parola politikaları** ve varsayılan yapılandırma hataları incelenmiştir. 
* **Güvenlik Sonuçları:** Saldırganların kaba kuvvet yöntemleriyle "root" erişimi sağlamasına olanak tanıyan bu açıklar, Aegis-SSH ile simüle edilerek sistem yöneticilerine zafiyetin kritikliğini (RCE riski) raporlar.

## 🛡️ Zafiyet Çözümü ve Savunma Stratejileri

Aegis-SSH tarafından tespit edilen zafiyetlerin giderilmesi için şu savunma mekanizmaları uygulanmalıdır:
1. **Anahtar Tabanlı Doğrulama:** Parola ile girişler tamamen kapatılmalıdır (`PasswordAuthentication no`).
2. **Fail2Ban:** Hatalı deneme yapan IP'lerin otomatik bloklanması sağlanmalıdır.
3. **Port Knocking:** SSH portu varsayılan 22 değerinden farklı bir değere taşınmalıdır.

## 🔮 Üretim ve Gelecek Vizyonu

Aegis-SSH şu anki haliyle Dockerize edilmiş ve CI/CD süreçlerine entegre edilmiştir. Üretim ortamında (Production) şu şekilde genişletilebilir:
- **Protokol Çeşitliliği:** Sadece SSH değil; FTP, RDP ve Telnet servisleri için de asenkron denetim modülleri eklenecektir.
- **Web Dashboard:** Tarama sonuçlarının anlık izlenebileceği bir merkezi yönetim arayüzü entegre edilecektir.
- **API Entegrasyonu:** Shodan API'si ile açık port keşfi otomatiğe bağlanacaktır.

## 🚀 Kurulum

```bash
# Depoyu klonlayın
git clone [https://github.com/Winslowe/Aegis-SSH.git](https://github.com/Winslowe/Aegis-SSH.git)
cd Aegis-SSH

# Gerekli bağımlılıkları yükleyin
pip install -r requirements.txt

# Aracı profesyonel src dizini yapısıyla çalıştırın
python src/main.py
