
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
* [🛠️ Mimari Yapı ve Karşılaştırma](#️-mimari-yapı-ve-karşılaştırma)
* [🎯 İncelenen Zafiyet: SSH Brute-Force](#-incelenen-zafiyet-zayıf-ssh-yapılandırması-ve-brute-force)
* [🛡️ Zafiyet Çözümü ve Savunma Stratejileri](#️-zafiyet-çözümü-ve-savunma-stratejileri)
* [🚀 Kurulum ve Çalıştırma](#-kurulum)
* [💬 Discord Webhook Entegrasyonu](#-discord-webhook-entegrasyonu)
* [⚠️ Yasal Uyarı](#️-yasal-uyarı)

---

## ✨ Temel Özellikler

- ⚡ **Asenkron İletişim:** Python'un `asyncio` kütüphanesi ve `Semaphore` mekanizması sayesinde sistem kaynaklarını tüketmeden aynı anda onlarca bağlantı açabilir.
- 🌐 **Alt Ağ (Subnet) Taraması:** `192.168.1.0/24` gibi koca bir alt ağı otomatik çözümleyerek açık SSH portlarını saniyeler içinde tarar.
- 🥷 **Gelişmiş Evasion (Kaçınma):** Güvenlik duvarlarını atlatabilmek için dinamik *Jitter* (Zamanlama manipülasyonu) ve *Client Fingerprint Spoofing* özelliklerine sahiptir.
- 📊 **HTML Raporlama:** Tarama bittiğinde zafiyet durumunu içeren okunaklı bir `.html` raporu otomatik olarak oluşturulur.
- 💾 **Oturum Yönetimi:** Beklenmedik kesintilerde süreç `session.json` dosyasına kaydedilir ve kaldığı yerden devam eder.

## 🛠️ Mimari Yapı ve Karşılaştırma

Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde **"Event Loop"** mimarisiyle yönetir. Klasik çoklu-iş parçacıklı (Multi-threaded) scriptlerin aksine, "Socket Exhaustion" hatalarını önlemek için `asyncio.Semaphore` kullanarak hedefin kapasitesine göre eşzamanlılık sınırı koyar.



## 🎯 İncelenen Zafiyet: Zayıf SSH Yapılandırması ve Brute-Force

Bu projede, sunucularda en sık karşılaşılan **zayıf parola politikaları** incelenmiştir. Sistem yöneticilerinin varsayılan ayarları değiştirmemesi veya zayıf şifreler kullanması, saldırganların kaba kuvvet (brute-force) yöntemleriyle sistemde yetkisiz "root" erişimi sağlamasına yol açmaktadır. Aegis-SSH, bu riskleri kurumlar için görünür kılar.

## 🛡️ Zafiyet Çözümü ve Savunma Stratejileri

Aegis-SSH tarafından tespit edilen zafiyetleri önlemek için şu adımlar kritiktir:
1. **Anahtar Tabanlı Doğrulama:** Parola ile giriş tamamen kapatılmalıdır (`PasswordAuthentication no`).
2. **Fail2Ban Kullanımı:** Arda arda gelen hatalı denemeler firewall seviyesinde engellenmelidir.
3. **Port Değiştirme:** Varsayılan 22 portu yerine alternatif portlar tercih edilmelidir.

## 🚀 Kurulum

```bash
# Depoyu klonlayın
git clone [https://github.com/Winslowe/Aegis-SSH.git](https://github.com/Winslowe/Aegis-SSH.git)
cd Aegis-SSH

# Gerekli bağımlılıkları yükleyin
pip install -r requirements.txt

# Aracı çalıştırın (Profesyonel src dizini yapısı)
python src/main.py
### 🏫 İSTİNYE ÜNİVERSİTESİ - MESLEK YÜKSEKOKULU
**Program:** Bilişim Güvenliği Teknolojisi  
**Ders:** Sızma Testi (Penetrasyon)  
**Öğrenci:** Muhammet Eren Çapan  
**Eğitmen:** [Hocanın Adı]  
**Proje Tarihi:** Mart - Nisan 2026

