# ScanBuddy Telegram Bot

**ScanBuddy**, Telegram üzerinden dosya yükleyip bu dosyaları [VirusTotal](https://www.virustotal.com) API'si ile tarayan ve sonuçları raporlayan bir bottur.

## Özellikler

- Kullanıcıların yüklediği dosyaları VirusTotal API ile tarar.
- Sonuçları Telegram üzerinden kullanıcıya geri bildirir.
- Kolay kurulabilir ve kullanımı basittir.

## Gereksinimler

Bu projeyi çalıştırabilmek için aşağıdaki yazılımların sisteminizde kurulu olması gerekmektedir:

- Python 3.7 veya üzeri
- [Telegram Bot Token](https://core.telegram.org/bots#botfather)
- [VirusTotal API Anahtarı](https://www.virustotal.com/gui/join-us)

## Kurulum

### 1. Bu projeyi klonlayın

Öncelikle, projeyi yerel makinenize klonlayın ve proje dizinine geçin:

```bash
git clone https://github.com/kutaykoca/telegram-vt-bot
cd telegram-vt-bot
```

### 2. Sanal ortam oluşturun ve etkinleştirin (Opsiyonel)

Projedeki bağımlılıkları izole bir ortamda yönetmek için bir Python sanal ortamı oluşturabilirsiniz. Bu adım opsiyoneldir ancak tavsiye edilir.

#### MacOS/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Gereksinimleri yükleyin

Projenin çalışabilmesi için gerekli olan Python kütüphanelerini `requirements.txt` dosyasından yükleyin:

```bash
pip install -r requirements.txt
```

### 4. `.env` Dosyasını oluşturun

Projenizin çalışabilmesi için API anahtarlarını ve Telegram bot tokenini saklayan bir `.env` dosyası oluşturmanız gerekmektedir. Proje dizininde bir `.env` dosyası oluşturun ve aşağıdaki gibi doldurun:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
```

Bu dosya, API anahtarlarınızı ve bot tokeninizi saklamak içindir. `.env` dosyasını GitHub gibi açık kaynak platformlarda paylaşmayın ve `.gitignore` dosyasına ekleyin.

### 5. Botu çalıştırın

Artık botu çalıştırmaya hazırsınız. Aşağıdaki komut ile botu başlatın:

```bash
python telegram-vt-bot.py
```

Bot başarıyla çalıştıysa, Telegram üzerinden `/start` komutu ile botu başlatabilirsiniz. Bot, size bir dosya yüklemenizi söyleyecek ve ardından bu dosyayı VirusTotal API ile tarayarak sonuçları size bildirecektir.

## Kullanım

1. Telegram'da botunuzu başlatmak için `/start` komutunu gönderin.
2. Size bir dosya yüklemenizi söyleyen bir mesaj alacaksınız.
3. Yüklediğiniz dosya VirusTotal API'si ile taranacak ve sonuçlar size Telegram üzerinden iletilecektir.

## Proje Yapısı

```plaintext
telegram-vt-bot/
│
├── telegram-vt-bot.py     # Ana Python dosyası
├── .env                   # API anahtarlarını saklar (bu dosya .gitignore'da listelenmiştir)
├── requirements.txt       # Gerekli bağımlılıkları listeler
└── README.md              # Bu dokümantasyon
```

## Geliştime

Bu projeye katkıda bulunmak istiyorsanız, projeyi fork'layarak değişikliklerinizi ekleyebilir, ardından pull request açabilirsiniz. Her türlü geri bildirime açığım.