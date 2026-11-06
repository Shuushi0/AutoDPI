# AutoDPI

macOS ve Windows'ta çalışan küçük bir arka plan servisi: **SNI tabanlı DPI engelini ve DNS zehirlemesini**
tüm sistem için, VPN hesabı olmadan aşar. Engellenen bağlantıyı fark eder, o bağlantıyı hemen onarır,
siteyi bulunduğunuz ağ için hatırlar, sonraki bağlantıları çalışan yoldan geçirir. Tarayıcılar,
her uygulama: ağ katmanında çalıştığı için hepsini kapsar.

English: [README.md](README.md)

## Kurulum

[Sürümler sayfasından](https://github.com/Shuushi0/AutoDPI/releases) sisteminize uygun arşivi indirin
(ya da aşağıdaki gibi kendiniz derleyin).

**macOS (Apple Silicon, macOS 13+)**

```bash
unzip autodpi-macos-arm64-*.zip && cd autodpi-macos-arm64-*
xattr -dr com.apple.quarantine .        # dosyalar Apple tarafından notarize edilmedi
sudo ./autodpi install                  # root launchd servisi, açılışta başlar
autodpi status
cp -R AutoDPI.app /Applications/ && open /Applications/AutoDPI.app   # isteğe bağlı menü çubuğu uygulaması
```

Kaldırmak için `sudo autodpi uninstall [--purge]` (`--purge` öğrenilen listeleri de siler).

**Windows 10 (1803 ve sonrası) ya da 11, 64 bit**: zip'in tamamını bir klasöre çıkarın ve `AutoDPI.cmd`
dosyasına çift tıklayın. Yönetici izni ister ve bir menü açar: kurulum, durum ve liste, kontrol paneli,
duraklat ve sürdür, ağ ölçümü, kurmadan beş dakikalık deneme, hata bildirimi için rapor, kaldırma ve acil
fren. Yönetici terminalinde `.\autodpi.exe install` ve `.\autodpi.exe uninstall [--purge]` menüdeki kurma
ve kaldırmanın aynısını yapar. Menüyü adım adım anlatan rehber: [docs/windows-test.md](docs/windows-test.md).
Tepsi penceresi Edge WebView2 çalışma ortamını kullanır (Windows 11'de ve güncel Windows 10'da vardır);
yoksa ayar sayfası tarayıcıda açılır.

Başka bir VPN'i (örneğin Cloudflare WARP) önce kapatın: bir tünel trafiği sahiplenirken servis kendiliğinden
beklemede kalır, tünel kalkınca devreye girer. Windows'ta GoodbyeDPI ve zapret için de aynısı geçerli: aynı
paketleri değiştirdikleri için servis onlar kapanana kadar bekler (menüde G tuşu onları durdurur).

## Uygulamalar

- **macOS menü çubuğu uygulaması** (`AutoDPI.app`): menü çubuğunda durumun rengini alan bir kalkan.
  Tıklayınca açılan pencerede durum ve duraklat düğmesi, şu anki ağ, sayaçlar (liste, direkt, yedek
  motor), son olaylar ve arama kutulu öğrenilen liste var. "Ayarları Aç" ayar sayfasını açar; güç
  düğmesi servisi kapatır (ve çıkar) ya da yalnızca uygulamadan çıkar. Servis kapalıysa pencere onu
  başlatmayı önerir (yönetici parolası).
- **Windows tepsi uygulaması** (`autodpi-tray.exe`, `install` kurar): bildirim alanında aynı kalkan.
  Tıklayınca macOS penceresiyle aynı içerikte küçük bir pencere açılır; sağ tık duraklat ve sürdür, ayar
  sayfası, servisi başlat, simgeyi gizle ve çıkış seçeneklerini verir. Her oturum açılışında başlar;
  "simgeyi gizle" seçilirse servis simgesiz çalışmaya devam eder, Başlat menüsünden AutoDPI açılınca simge
  geri gelir.
- **Ayar sayfası** (`autodpi ui`, Windows'ta `AutoDPI Panel.cmd`): tarayıcıda, yalnızca bu bilgisayardan
  erişilen yerel bir sayfa. Sekmeleri:
  - *Genel bakış*: durum ve trafik için anlamı, trafik çubuğu (direkt, motor ile, geçiş), ağ, motor
    sırası, servis, en son liste kayıtları ve olaylar.
  - *Liste*: bu ağın ya da bütün ağların öğrenilen siteleri; arama, kaynak süzgeci ve sıralama; elle
    site ekleme ve çıkarma.
  - *Ayarlar*: motor sırası, sahte SNI, dil, yeniden test aralığı, yedek motor gecikmesi, DNS devralma
    ve QUIC engelleme. Kaydetmek yönetici izni ister; uygulanması için servisi yeniden başlatın.
  - *Bakım*: yakalamayı yenile, DNS önbelleğini temizle, listeyi yeniden sına, açık alan adlarını
    sıfırla, servisi yeniden başlat, günlükleri temizle, bu ağın ya da bütün ağların listesini sıfırla.
  - *Günlük*: olay kaydı; türe göre süzülür, aranabilir.

## Dil

Okuduğunuz her şey Türkçe ve İngilizce: komut satırı, uygulamalar, sayfa ve Windows menüsü. Sistemin dili
belirler (Türkçeyse Türkçe, değilse İngilizce). Seçmek için ayar sayfasında **Dil**'i değiştirin
(`config.json` içinde `"language": "tr"` ya da `"en"`), ya da tek bir komut için `AUTODPI_LANG=tr|en`.

## Kullanım

```
autodpi status                 durum, ağ, sayaçlar
autodpi list [--all]           bu ağ için öğrenilen engelli siteler (--all: bütün ağlar)
autodpi add <alan-adı> [motor] elle ekle (kalıcı)             autodpi remove <alan-adı>
autodpi test <host> [--all]    hedefi şimdi dene; --all bütün motorları dener
autodpi pause | resume         bypass'ı kapat / aç
autodpi networks               bilinen ağlar
autodpi log [-n 50]            onarılan ve listeye alınan siteler, durum değişiklikleri
autodpi maint <eylem>          clear-logs | restart | shutdown | flush-dns | retest |
                               reset-list | reset-all-lists | reconcile (sudo gerekmez)
autodpi update [install|skip]  yeni sürümü denetle (install: şimdi kur; skip: bu sürümü atla)
autodpi ui [--no-open]         tarayıcıda ayar sayfası
autodpi doctor | lab           tanı, başka araçların DNS kuralları dahil (lab: bu ağda hangi teknik neyi açıyor)
```

Acil fren: macOS klasöründeki `./restore-network.sh` ya da Windows'ta klasördeki `restore-network.ps1`
(`AutoDPI.cmd` menüsünde 0) her şeyi durdurur ve DNS'i geri koyar. Kaynak ağacında ikisi de `scripts/`
altında.

## Nasıl çalışır

```
uygulama ─► sing-box TUN ─┬─ bu ağda engelli site ─► motor ─► internet
           (tüm trafik)    └─ diğer TCP/443 ─► gözlemci ─ önce gerçek yolu dener;
                                                          RST ya da sahte cevap gelirse aynı ClientHello'yu
                                                          bir motordan tekrarlar (ilk deneme açılır),
                                                          sonra doğrular ve siteyi listeler
```

- **Motorlar**, sırayla: `tlsrec` (ClientHello'yu iki TLS kaydına böler), `ciadpi` (byedpi desync zinciri), `tlsspoof` (sahte ClientHello, yalnızca root).
- **Öğrenme ağa özeldir** (ISS'nin AS numarasına göre) ve kayıt edilebilir alan adı olarak tutulur. Art arda
  birkaç kez direkt açılan site bellekte önbelleğe alınır ve hafif yoldan geçer; sonradan engellenirse F5'te
  açılır ve listeye girer. Yalnızca RST ya da enjekte edilmiş cevap engel sayılır; hat takılması hiçbir şeyi
  listeye sokmaz.
- **DNS**: servis aktifken sistem çözücüsü 1.1.1.1'e bakar, TUN bunu DoH ile yanıtlar (iki çözücü, yedekli);
  asıl ayarınız kaydedilir ve durunca geri yüklenir. QUIC yalnızca listedeki siteler için reddedilir ki o
  uygulamalar TCP'ye insin. IPv6 yalnızca ağda varsa yakalanır.
- **Fail-open**: yardımcı süreçler daemon'la birlikte ölür, sağlık denetimi kalıcı düşerse yakalama bırakılır,
  yeniden devreye girme geri çekilmeyle yapılır. Gerçek kullanım yaklaşık 70 MB ve tek çekirdeğin ~%2'si.

## Güncellemeler

Servis günde bir kez GitHub'da yeni sürüm olup olmadığına bakar. Varsa indirir, sürümün imzasını
denetler (kurulu kopya yalnızca projenin anahtarıyla imzalanmış arşivleri kabul eder) ve bağlantı
boştayken kurar; servis birkaç saniyeliğine yeniden başlar. Düzgün açılmayan yeni sürümün yerine önceki
sürüm geri gelir ve onu bir daha kendiliğinden kurmaz. Otomatik güncelleme kapalıyken menü çubuğu
uygulaması, tepsi penceresi ve sayfa yeni sürümü Güncelle, Notlar ve Atla düğmeleriyle duyurur. İki ayar
da sayfada Ayarlar → Güncellemeler'dedir ve yeniden başlatma gerektirmez; menü çubuğu uygulamasında ve
tepsi penceresinde sürüm satırının yanında Güncellemeleri denetle vardır.

## Ayarlar

Durum dosyasının yanındaki isteğe bağlı `config.json` (macOS'ta `/Library/Application Support/AutoDPI/`,
Windows'ta `%ProgramData%\AutoDPI\`) ya da ayar sayfası. Uygulanması için servisi yeniden başlatın
(`autodpi maint restart` ya da sayfada Bakım).

| anahtar | varsayılan | anlamı |
|---|---|---|
| `engines` | `["tlsrec","ciadpi","tlsspoof"]` | motor sırası |
| `doh_servers` | `["1.1.1.1","1.0.0.1"]` | DoH çözücüleri (IP adresi) |
| `dns_takeover` | `true` | sistem çözücüsünü TUN'a yönlendir |
| `block_quic` | `true` | listedeki siteler için QUIC'i reddet |
| `escalate_on_silence` | `false` | yalnız zaman aşımı alan bağlantıda tüm motorları dene (paketleri sessizce düşüren ağlar) |
| `local_domains` | `[]` | ağın kendi DNS'inin cevaplayacağı ek alan adları (şirket, okul ağları); `.local`, `.lan`, `.corp`, `.internal` ve tek kelimelik adlar her zaman öyle |
| `retest_hours` | `3` | listedeki sitelerin yeniden kontrol sıklığı |
| `spoof_sni` | `www.google.com` | `tlsspoof` için sahte ad |
| `auto_update` | `true` | yeni sürümü bağlantı boştayken kendiliğinden kur; kapalıyken yalnızca duyurulur |
| `update_check_hours` | `24` | yeni sürüme ne sıklıkla bakılacağı; `0`: yalnızca istenince |
| `language` | (sistemin dili) | `"tr"` ya da `"en"`: komut satırı, uygulamalar ve sayfanın dili |
| `hedge_ms`, `first_byte_ms`, `max_conn`, `ciadpi_args`, `ipv4_only`, `warp_profile` | | ileri düzey |

## Kaynaktan derleme

Apple Silicon bir Mac'te Go, Xcode Command Line Tools (clang ve swiftc) ve curl gerekir. Daemon'ın içine
gömdüğü her şey sabitlenmiş ve sağlama toplamıyla doğrulanır: sing-box 1.14.4 yalnızca gereken etiketlerle
kaynaktan derlenir (`tools/singbox`), byedpi 0.17.3 sürüm arşivinden.

```bash
scripts/release.sh 0.1.1        # dist/release/*.zip: macOS ve Windows (çapraz derleme) + SHA256SUMS
go test -race ./...             # testler; scripts/dev/e2e-notun.sh bütün hattı root'suz çalıştırır
```

`scripts/fetch-bins.sh`, `build.sh`, `build-app.sh` ve `*-windows.sh` adımları ayrı ayrı yapar.

## Sınırlar

Yalnızca TCP/443 (ses görüşmeleri gibi yalnızca-UDP engeller ele alınmaz); yalnızca-IPv6 ağlar desteklenmez;
ECH ile SNI görünmez; macOS sürümü yalnızca Apple Silicon, Windows sürümü yalnızca amd64. Bu bir root
servisi: çalıştırmadan önce kodu okuyun.

## Yasal uyarı ve sorumluluk reddi

**Sunucu ve veri.** AutoDPI kendi cihazınızda çalışır. Projenin işlettiği bir sunucu yoktur: trafiğiniz
projeden geçmez; gezinme bilgileriniz, site listeleriniz ve kullanım verileriniz projeye gönderilmez.
Uygulama, açtığınız sitelere, DNS için Cloudflare'e (1.1.1.1, 1.0.0.1), bağlantı denetimi için ağınızın DNS
sunucularına ve güncellemeler için GitHub'a bağlanır. Hata raporu yalnızca bilgisayarınızda oluşturulur ve
kendiliğinden gönderilmez. Alan adları, DNS kuralları, hosts kayıtları ve yerel ağ adresleri içerebilir;
paylaşmadan önce içine bakın.

**Amaç.** Kişisel kullanım ve yasal içeriğe yönelik ağ düzeyindeki sansürü aşmak için tasarlandı. Yasalara
aykırı amaçlarla, başkalarının hesaplarına veya sistemlerine yetkisiz erişim için, ağ altyapısına zarar
vermek ya da aşırı yük bindirmek için kullanmayın. AutoDPI hesap bilgisi istemez ve sizin adınıza hiçbir
ağa veya hizmete giriş yapmaz.

**Riskler.** Filtreleri aşmak; yurt, kampüs, iş yeri veya kamusal Wi-Fi gibi bağlandığınız ağın kullanım
koşullarına aykırı olabilir. Bu, erişimin kısıtlanması, hesabın askıya alınması veya disiplin işlemi gibi
sonuçlar doğurabilir. Bir içeriğe erişim mahkeme veya idari kararla engellenmiş olabilir. Bulunduğunuz
yerin yasalarını ve bağlandığınız ağın koşullarını kontrol etmek size aittir.

**VPN değildir.** AutoDPI trafiğinizi şifrelemez, IP adresinizi gizlemez ve anonimlik sağlamaz. Ağınız ve
internet sağlayıcınız hangi sunuculara bağlandığınızı görmeye devam edebilir.

**Sorumluluk reddi.** Kullanım tümüyle kendi kararınız ve sorumluluğunuzdadır. Yazılım "olduğu gibi" ve
garantisiz sunulur; bir sitenin açılacağı, bağlantının kesintisiz veya güvenli olacağı garanti edilmez.
Geliştiricileri, yasaların izin verdiği ölçüde, kullanımından doğan doğrudan veya dolaylı zararlardan,
veri kaybından, hizmet kesintisinden ve yaptırımlardan sorumlu değildir (GPL-3.0, 15. ve 16. bölümler). Bu
metin hukuki danışmanlık değildir.

## Lisans

Copyright (C) 2026 Shuushi0.

GPL-3.0-or-later, bkz. [LICENSE](LICENSE). Sürüm dosyaları sing-box (GPL-3.0-or-later), byedpi (MIT) ve
birkaç Go modülü içerir; bkz. [THIRD_PARTY.md](THIRD_PARTY.md).
