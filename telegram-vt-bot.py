import requests
import os
import asyncio
from telegram import Update, ForceReply
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
from dotenv import load_dotenv

# .env dosyasındaki değişkenleri yükleyin
load_dotenv()

# API ayarları
API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files'
ANALYSES_URL = 'https://www.virustotal.com/api/v3/analyses'

# Bot tokeninizi .env dosyasından alıyoruz
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')

async def start(update: Update, context: CallbackContext):
    """Bot başlangıç komutu."""
    user = update.effective_user
    await update.message.reply_html(
        rf"Merhaba {user.mention_html()}! Lütfen dosyanızı yükleyin.",
        reply_markup=ForceReply(selective=True),
    )

async def handle_document(update: Update, context: CallbackContext):
    """Kullanıcının yüklediği dosyayı tarar."""
    document = update.message.document
    file = await document.get_file()
    file_path = f'./{document.file_name}'
    await file.download_to_drive(file_path)

    # Dosyayı VirusTotal API'sine yükle
    with open(file_path, 'rb') as f:
        headers = {
            "x-apikey": API_KEY
        }
        response = requests.post(VIRUSTOTAL_URL, headers=headers, files={'file': f})

    # API yanıtını kontrol et
    if response.status_code == 200:
        json_response = response.json()
        # Yüklenen dosyanın scan ID'sini al
        scan_id = json_response['data']['id']
        await update.message.reply_text(f"Dosyanız yüklendi. Sonuçlar için lütfen biraz bekleyin. (Scan ID: {scan_id})")
        # Sonuçları kontrol et
        await check_scan_result(update, scan_id)
    else:
        await update.message.reply_text(f"Dosya yüklenirken bir hata oluştu: {response.text}")

    # İstenmeyen dosyayı sil
    os.remove(file_path)

async def check_scan_result(update: Update, scan_id: str):
    """VirusTotal'dan sonuçları kontrol eder."""
    headers = {
        "x-apikey": API_KEY
    }
    result_url = f"{ANALYSES_URL}/{scan_id}"

    # Sonuçları almak için biraz bekleyin
    await update.message.reply_text("Sonuçlar işleniyor, lütfen birkaç saniye bekleyin...")
    await asyncio.sleep(15)  # 15 saniye bekleyin

    response = requests.get(result_url, headers=headers)

    # Yanıtı yazdırarak kontrol edelim
    print(f"VirusTotal API yanıtı: {response.text}")  # Yanıtın tamamını görmek için

    if response.status_code == 200:
        json_response = response.json()
        if 'data' in json_response:
            attributes = json_response['data']['attributes']
            stats = attributes['stats']
            malicious_count = stats['malicious']
            if malicious_count > 0:
                await update.message.reply_text("Zararlı yazılım tespit edildi! Hemen sil! ☣️⚠️🆘")
            else:
                await update.message.reply_text("Dosya tertemiz ✅")
        else:
            await update.message.reply_text("Sonuçlar alınamadı.")
    else:
        # Hata mesajını doğrudan yazdır
        await update.message.reply_text(f"Sonuçları kontrol ederken bir hata oluştu: {response.text}")

def main():
    """Botu başlatır."""
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Komutları ve mesajları işlemek için handler ekleyin
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    # Botu çalıştır
    application.run_polling()

if __name__ == '__main__':
    main()