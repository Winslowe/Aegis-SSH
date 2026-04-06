# 🏫 İSTİNYE ÜNİVERSİTESİ - MESLEK YÜKSEKOKULU
**Program:** Bilişim Güvenliği Teknolojisi  
**Ders:** Sızma Testi (Penetrasyon)  
**Öğrenci:** Muhammet Eren Çapan  
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
* [🛠️ Mimari Yapı](#️-mimari-yapı-ve-karşılaştırma)
* [🎯 İncelenen Zafiyet: SSH Brute-Force](#-incelenen-zafiyet-zayıf-ssh-yapılandırması-ve-brute-force)
* [🛡️ Zafiyet Çözümü ve Savunma](#️-zafiyet-çözümü-ve-savunma-stratejileri)
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

## 🛠️ Mimari Yapı ve Karşılaştırma

Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde **"Event Loop"** mimarisiyle yönetir. Klasik çoklu-iş parçacıklı (Multi-threaded) scriptlerin aksine, "Socket Exhaustion" hatalarını önlemek için `asyncio.Semaphore` kullanarak rate-limiting uygular. Bu sayede tarama yapılan sistemin stabilitesi korunur.

## 🎯 İncelenen Zafiyet: Zayıf SSH Yapılandırması ve Brute-Force

Bu projede, kurumsal sunucularda en sık rastlanan **zayıf parola politikaları** ve **varsayılan yapılandırma hataları** incelenmiştir. Saldırganların kaba kuvvet yöntemleriyle "root" erişimi sağlamasına olanak tanıyan bu açıklar, Aegis-SSH ile simüle edilerek sistem yöneticilerine raporlanır.

## 🛡️ Zafiyet Çözümü ve Savunma Stratejileri

Tespit edilen zafiyetlerin giderilmesi için şu güvenlik önlemleri uygulanmalıdır:
1. **Anahtar Tabanlı Doğrulama:** Parola ile girişler kapatılmalıdır (`PasswordAuthentication no`).
2. **Fail2Ban:** Hatalı deneme yapan IP'lerin otomatik bloklanması sağlanmalıdır.
3. **Port Knocking:** SSH portu varsayılan 22 değerinden farklı bir değere taşınmalıdır.

## 🚀 Kurulum

```bash
# Depoyu klonlayın
git clone [https://github.com/Winslowe/Aegis-SSH.git](https://github.com/Winslowe/Aegis-SSH.git)
cd Aegis-SSH

# Gerekli bağımlılıkları yükleyin
pip install -r requirements.txt

# Aracı profesyonel src dizini yapısıyla çalıştırın
python src/main.py
