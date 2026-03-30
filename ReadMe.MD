# 🛡️ Aegis-SSH Auditing Suite

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)

Aegis-SSH, kurumsal ağlarda veya dışa açık sunucularda unutulmuş, zayıf yapılandırılmış SSH servislerinin güvenliğini denetlemek amacıyla geliştirilmiş yüksek performanslı bir **Asenkron Sızma Testi (Pentest)** aracıdır.

## ✨ Temel Özellikler

- ⚡ **Asenkron İletişim:** Python'un `asyncio` kütüphanesi ve `Semaphore` mekanizması sayesinde sistem kaynaklarını tüketmeden aynı anda onlarca bağlantı açabilir.
- 🌐 **Banner Grabbing & Versiyon Tespiti:** Brute-force işleminden önce hedef porttaki SSH versiyonunu okuyarak, eski ve bilinen zafiyetleri (CVE) olan OpenSSH sürümlerinin analiz edilmesine olanak tanır.
- 🔒 **Sessiz ve Kararlı:** Geleneksel threading yapılarının aksine "Connection Refused" veya timeout hatalarını zarifçe tolere eder. `asyncssh` kütüphanesinin public key (StrictHostKeyChecking) doğrulama aşamalarını atlayarak hız kazanır.
- 🎨 **Dinamik Konsol Arayüzü:** Başarılı sızma denemelerini anında yeşil, hatalı yapılandırmaları kırmızı ile belirten modern bir komut satırı deneyimi sunar.

## 🛠️ Mimari Yapı ve Karşılaştırma

Aegis-SSH, asenkron I/O operasyonlarını tek bir thread üzerinde "Event Loop" mimarisiyle yönetir. Tıpkı Rust dilindeki `tokio::sync::Semaphore` yapısına benzer şekilde, `asyncio.Semaphore` kullanılarak hedef sunucunun ve ağın DDoS (Denial of Service) durumuna düşmesi engellenir. İşletim sistemi seviyesindeki kilitlenmelerin önüne geçilir.

## 🚀 Kurulum

Sisteminizde Python 3.8 veya üzeri bir sürüm kurulu olmalıdır:

```bash
git clone [https://github.com/Winslowe/Aegis-SSH.git](https://github.com/Winslowe/Aegis-SSH.git)
cd Aegis-SSH
pip install -r requirements.txt