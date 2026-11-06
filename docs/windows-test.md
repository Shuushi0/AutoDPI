# Windows'ta AutoDPI, adım adım

Bu rehber AutoDPI'yı Windows'ta kurmayı ve her parçanın çalıştığını kontrol etmeyi adım adım anlatır.
Her şey tek bir menüden yapılıyor, komut yazmak gerekmiyor.

Gerekenler: Windows 10 (1803 ve sonrası) ya da 11, 64 bit, yönetici hesabı. Açık bir VPN varsa
(Cloudflare WARP dahil) kapat. **GoodbyeDPI ya da zapret** açıksa onları da kapat: aynı paketleri
değiştirirler, ikisi birlikte sitelerde `ERR_SSL_PROTOCOL_ERROR` verdirir. Menü bunları görürse kırmızı uyarı
gösterir; **G** tuşu durdurur (hizmet olarak kuruluysa açılışta başlamasını da kapatır).

## Başlarken

1. [Releases](https://github.com/Shuushi0/AutoDPI/releases) sayfasından `autodpi-windows-amd64-*.zip` dosyasını indir.
2. Zip'e sağ tıkla → **Tümünü ayıkla**, örneğin masaüstüne çıkar. Zip'in içinden çalıştırma.
3. Çıkan klasörde **`AutoDPI.cmd`** dosyasına çift tıkla, yönetici izni sorulunca **Evet** de.
   (`autodpi.exe`'ye çift tıklama: komut satırı programıdır, pencere açılıp hemen kapanır.)

İmzasız olduğu için SmartScreen "Windows bilgisayarınızı korudu" diyebilir: **Ek bilgi** → **Yine de çalıştır**.
Defender bir dosyayı karantinaya alırsa not et ve bildir; antivirüsü kapatma.

Açılan menünün en üstünde servisin durumu yazar (KURULU DEĞİL / ÇALIŞIYOR).

## Adımlar (menü tuşları)

1. **6 Ağ ölçümü**: hiçbir şeyi değiştirmez, hangi tekniğin bu ağda neyi açtığını ölçer. Birkaç dakika sürer.
2. **7 Deneme çalıştırması**: kurmadan 5 dakika çalışır. Bu sırada tarayıcıda google.com, sonra açılmayan
   sitelerini dene (engelli site ilk denemede ya da bir yenilemeden sonra açılmalı). Bitince internetin normal
   çalıştığını kontrol et.
3. **1 Kur**: açılışta başlayan bir Windows hizmeti olarak kurar. Engelli siteleri tekrar dene.
4. **Tepsi simgesi**: kurulumdan sonra sağ altta (saatin yanında, gerekirse ^ okunun içinde) kalkan simgesi çıkar.
   Rengi durumu gösterir (yeşil = aktif). **Tıkla**: durum, liste ve son olaylar küçük bir pencerede açılır; dışarı
   tıklayınca kapanır. **Sağ tıkla**: duraklat/sürdür, ayarlar, simgeyi gizle, simgeyi kapat, servisi kapat.
   "Simgeyi gizle"yi dene: simge kaybolmalı, siteler açılmaya devam etmeli; Başlat menüsünde **AutoDPI**'yi açınca
   simge geri gelmeli. Küçük pencere yerine tarayıcı açılırsa Edge WebView2 çalışma ortamı eksiktir; ayarlar o
   zaman tarayıcıda açılır.
5. **3 Kontrol paneli** (ya da klasördeki **`AutoDPI Panel.cmd`**): tarayıcıda tam panel; sekmeleri Genel bakış,
   Liste, Ayarlar, Bakım ve Günlük. Ayarlarda **Dil**'i değiştirip Kaydet: sayfa yeni dilde yenilenir. Menü yönetici
   olarak çalıştığı için buradan açılan panel kaydederken izin sormaz. Tepsi simgesinin **Ayarlar (tarayıcıda)**
   seçeneğiyle ya da küçük penceredeki **Ayarları Aç** ile açılan panelde ise Kaydet, Windows'un yönetici izni
   penceresini (UAC) açar: **Evet** de. Dil hemen değişir; diğer ayarlar için Bakım sekmesinden servisi yeniden başlat.
6. **4 Duraklat** ve **5 Sürdür**: duraklatınca engelli siteler açılmamalı, sürdürünce yine açılmalı.
7. Bilgisayarı **yeniden başlat**: oturum açılınca tepsi simgesi kendiliğinden gelmeli, internet normal olmalı.
8. **8 Rapor topla**: masaüstüne `autodpi-rapor.zip` yazar.
9. **9 Kaldır**: önce onay ister (**E** yaz), sonra her şeyi siler (öğrenilen listeler, tepsi simgesi ve Başlat
   menüsü kaydı dahil). Sonra internetin normal çalıştığını kontrol et.

## Bir şey ters giderse

- İnternet ya da DNS bozulursa menüde **0 Acil fren**. Düzelmezse bilgisayarı yeniden başlat.
- Menü açılmazsa: Başlat'a sağ tıkla → **Terminal (Yönetici)**, klasöre girip
  `powershell -ExecutionPolicy Bypass -File .\autodpi-menu.ps1` çalıştır ve görünen hatayı not et.
- Her hatanın ekran görüntüsünü al; **8 Rapor topla** ile raporu hazırla.

## Sorun bildirirken

- `autodpi-rapor.zip` (Windows sürümü, servis durumu, liste, günlükler, ağ ölçümü ve deneme kayıtları içinde).
- İnternet sağlayıcısı (Türk Telekom, Turkcell Superonline, Vodafone…, ev/mobil).
- Hangi sitelerin açılıp açılmadığı, deneme ve kaldırma sonrası internetin durumu, hata ekran görüntüleri.

Raporda parola veya hesap bilgisi yok. Alan adları, ağ sağlayıcısının adı, yerel ağ adresleri, DNS kuralları,
hosts kayıtları ve 53. portu kullanan programların adları olur; paylaşmadan önce içine bakın.
