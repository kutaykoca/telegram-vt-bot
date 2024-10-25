import requests
import os
import asyncio
from telegram import Update, ForceReply
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
)
from dotenv import load_dotenv

# .env dosyasından değişkenleri yükleyin
load_dotenv()

# API ayarları
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_URL = 'https://www.virustotal.com/api/v3/files'
VIRUSTOTAL_URL_SCAN = 'https://www.virustotal.com/api/v3/urls'
VIRUSTOTAL_IP_LOOKUP = 'https://www.virustotal.com/api/v3/ip_addresses'
VIRUSTOTAL_HASH_LOOKUP = 'https://www.virustotal.com/api/v3/files/'

ANALYSES_URL = 'https://www.virustotal.com/api/v3/analyses'

# Bot tokeninizi .env dosyasından alın
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

async def start(update: Update, context: CallbackContext):
    """Bot başlangıç komutu."""
    user = update.effective_user
    await update.message.reply_html(
        rf"Merhaba {user.mention_html()}. Dosya, URL, IP adresi veya Hash değeri göndererek tarama yapabilirsiniz.",
        reply_markup=ForceReply(selective=True),
    )

async def handle_document(update: Update, context: CallbackContext):
    """Kullanıcının yüklediği dosyayı tarar."""
    document = update.message.document
    file = await document.get_file()
    file_path = f'./{document.file_name}'
    await file.download_to_drive(file_path)

    try:
        # Dosyayı VirusTotal API'sine yükle
        with open(file_path, 'rb') as f:
            headers = {
                "x-apikey": API_KEY
            }
            response = requests.post(VIRUSTOTAL_FILE_URL, headers=headers, files={'file': f})

        # API yanıtını kontrol et
        if response.status_code == 200:
            json_response = response.json()
            # Yüklenen dosyanın scan ID'sini al
            scan_id = json_response['data']['id']
            await update.message.reply_text("Dosyanız yüklendi. Sonuçlar için lütfen biraz bekleyin.")
            # Sonuçları kontrol et
            await check_scan_result(update, scan_id)
        else:
            print(f"Dosya yüklenirken bir hata oluştu: {response.text}")
            await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    except Exception as e:
        print(f"Dosya işlenirken bir hata oluştu: {e}")
        await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    finally:
        # İstenmeyen dosyayı sil
        os.remove(file_path)

async def handle_text(update: Update, context: CallbackContext):
    """Metin mesajlarını (URL'ler, IP adresleri, hash değerleri) işler."""
    text = update.message.text.strip()

    # URL olup olmadığını kontrol et
    if text.startswith(('http://', 'https://')):
        await scan_url(update, text)
    # IP adresi olup olmadığını kontrol et
    elif is_valid_ip(text):
        await scan_ip(update, text)
    # Hash değeri olup olmadığını kontrol et
    elif is_valid_hash(text):
        await scan_hash(update, text)
    else:
        await update.message.reply_text("Lütfen geçerli bir URL, IP adresi veya Hash değeri girin.")

def is_valid_ip(ip: str) -> bool:
    """Girdiğin geçerli bir IP adresi olup olmadığını doğrular."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_hash(hash_str: str) -> bool:
    """Girdiğin geçerli bir MD5, SHA1 veya SHA256 hash değeri olup olmadığını kontrol eder."""
    import re
    hash_str = hash_str.lower()
    if re.fullmatch(r'[a-f0-9]{32}', hash_str):  # MD5
        return True
    elif re.fullmatch(r'[a-f0-9]{40}', hash_str):  # SHA1
        return True
    elif re.fullmatch(r'[a-f0-9]{64}', hash_str):  # SHA256
        return True
    return False

async def scan_url(update: Update, url: str):
    """URL'yi VirusTotal kullanarak tarar."""
    headers = {
        "x-apikey": API_KEY
    }
    data = {
        "url": url
    }
    try:
        response = requests.post(VIRUSTOTAL_URL_SCAN, headers=headers, data=data)

        if response.status_code == 200:
            json_response = response.json()
            analysis_id = json_response['data']['id']
            await update.message.reply_text("URL taranıyor. Lütfen bekleyin.")
            await check_scan_result(update, analysis_id)
        else:
            print(f"URL taranırken bir hata oluştu: {response.text}")
            await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    except Exception as e:
        print(f"URL taranırken bir hata oluştu: {e}")
        await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")

async def scan_ip(update: Update, ip: str):
    """IP adresini VirusTotal kullanarak sorgular."""
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.get(f"{VIRUSTOTAL_IP_LOOKUP}/{ip}", headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            malicious = json_response['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                await update.message.reply_text(f"IP adresi zararlı görünüyor! ☣️⚠️🆘")
            else:
                await update.message.reply_text("IP adresi temiz görünüyor ✅")
        else:
            print(f"IP adresi taranırken bir hata oluştu: {response.text}")
            await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    except Exception as e:
        print(f"IP adresi taranırken bir hata oluştu: {e}")
        await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")

async def scan_hash(update: Update, hash_str: str):
    """Hash değerini VirusTotal kullanarak sorgular."""
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.get(f"{VIRUSTOTAL_HASH_LOOKUP}{hash_str}", headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            attributes = json_response['data']['attributes']
            stats = attributes['last_analysis_stats']
            malicious = stats['malicious']
            if malicious > 0:
                await update.message.reply_text("Zararlı dosya tespit edildi! ☣️⚠️🆘️")
            else:
                await update.message.reply_text("Dosya temiz görünüyor ✅")
        else:
            print(f"Hash değeri taranırken bir hata oluştu: {response.text}")
            await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    except Exception as e:
        print(f"Hash değeri taranırken bir hata oluştu: {e}")
        await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")

async def check_scan_result(update: Update, scan_id: str):
    """VirusTotal'dan sonuçları kontrol eder."""
    headers = {
        "x-apikey": API_KEY
    }
    result_url = f"{ANALYSES_URL}/{scan_id}"

    # Sonuçların hazır olması için biraz bekleyin
    await asyncio.sleep(15)  # 15 saniye bekleyin

    try:
        response = requests.get(result_url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            if 'data' in json_response:
                attributes = json_response['data']['attributes']
                stats = attributes.get('stats') or attributes.get('last_analysis_stats')
                malicious_count = stats['malicious']
                if malicious_count > 0:
                    await update.message.reply_text("Zararlı içerik tespit edildi! Hemen önlem alın! ☣️⚠️🆘")
                else:
                    await update.message.reply_text("Temiz görünüyor ✅")
            else:
                print("Sonuçlar alınamadı.")
                await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
        else:
            print(f"Sonuçları kontrol ederken bir hata oluştu: {response.text}")
            await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")
    except Exception as e:
        print(f"Sonuçları kontrol ederken bir hata oluştu: {e}")
        await update.message.reply_text("Bir sorun oluştu. Lütfen daha sonra tekrar deneyin.")

def main():
    """Botu başlatır."""
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Komutları ve mesajları işlemek için handler ekleyin
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Botu çalıştır
    application.run_polling()

if __name__ == '__main__':
    main()
