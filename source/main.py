import os
import re
import requests
import urllib3
import concurrent.futures
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/goida-vpn-configs"
FINAL_FILENAME = "vlm"
# Ссылка на (raw) файл исходного репозитория для синхронизации списка URL
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
EXCLUDE_PROTOCOLS = ("ss://", "trojan://")

# Список SNI доменов
SNI_DOMAINS = [
    "00.img.avito.st", "01.img.avito.st", "02.img.avito.st", "03.img.avito.st",
    "04.img.avito.st", "05.img.avito.st", "06.img.avito.st", "07.img.avito.st",
    "08.img.avito.st", "09.img.avito.st", "10.img.avito.st", "1013a--ma--8935--cp199.stbid.ru",
    "11.img.avito.st", "12.img.avito.st", "13.img.avito.st", "14.img.avito.st",
    "15.img.avito.st", "16.img.avito.st", "17.img.avito.st", "18.img.avito.st",
    "19.img.avito.st", "1l-api.mail.ru", "1l-go.mail.ru", "1l-hit.mail.ru", "1l-s2s.mail.ru",
    "1l-view.mail.ru", "1l.mail.ru", "1link.mail.ru", "20.img.avito.st", "2018.mail.ru",
    "2019.mail.ru", "2020.mail.ru", "2021.mail.ru", "21.img.avito.st", "22.img.avito.st",
    "23.img.avito.st", "23feb.mail.ru", "24.img.avito.st", "25.img.avito.st",
    "26.img.avito.st", "27.img.avito.st", "28.img.avito.st", "29.img.avito.st", "2gis.com",
    "2gis.ru", "30.img.avito.st", "300.ya.ru", "31.img.avito.st", "32.img.avito.st",
    "33.img.avito.st", "34.img.avito.st", "3475482542.mc.yandex.ru", "35.img.avito.st",
    "36.img.avito.st", "37.img.avito.st", "38.img.avito.st", "39.img.avito.st",
    "40.img.avito.st", "41.img.avito.st", "42.img.avito.st", "43.img.avito.st",
    "44.img.avito.st", "45.img.avito.st", "46.img.avito.st", "47.img.avito.st",
    "48.img.avito.st", "49.img.avito.st", "50.img.avito.st", "51.img.avito.st",
    "52.img.avito.st", "53.img.avito.st", "54.img.avito.st", "55.img.avito.st",
    "56.img.avito.st", "57.img.avito.st", "58.img.avito.st", "59.img.avito.st",
    "60.img.avito.st", "61.img.avito.st", "62.img.avito.st", "63.img.avito.st",
    "64.img.avito.st", "65.img.avito.st", "66.img.avito.st", "67.img.avito.st",
    "68.img.avito.st", "69.img.avito.st", "70.img.avito.st", "71.img.avito.st",
    "72.img.avito.st", "73.img.avito.st", "74.img.avito.st", "742231.ms.ok.ru",
    "75.img.avito.st", "76.img.avito.st", "77.img.avito.st", "78.img.avito.st",
    "79.img.avito.st", "80.img.avito.st", "81.img.avito.st", "82.img.avito.st",
    "83.img.avito.st", "84.img.avito.st", "85.img.avito.st", "86.img.avito.st",
    "87.img.avito.st", "88.img.avito.st", "89.img.avito.st", "8mar.mail.ru", "8march.mail.ru",
    "90.img.avito.st", "91.img.avito.st", "92.img.avito.st", "93.img.avito.st",
    "94.img.avito.st", "95.img.avito.st", "96.img.avito.st", "97.img.avito.st",
    "98.img.avito.st", "99.img.avito.st", "99.img.avito.st", "9may.mail.ru", "a.auth-nsdi.ru", 
    "a.res-nsdi.ru", "a.wb.ru", "aa.mail.ru", "ad.adriver.ru", "ad.mail.ru", "adm.digital.gov.ru",
    "adm.mp.rzd.ru", "adv.ozon.ru", "afisha.mail.ru", "agent.mail.ru", "alfabank.ru",
    "alfabank.servicecdn.ru", "alfabank.st", "alpha3.minigames.mail.ru",
    "alpha4.minigames.mail.ru", "amigo.mail.ru", "ams2-cdn.2gis.com", "an.yandex.ru",
    "analytics.predict.mail.ru", "answer.mail.ru", "answers.mail.ru",
    "api-maps.yandex.ru", "api.2gis.ru", "api.a.mts.ru", "api.apteka.ru", "api.avito.ru",
    "api.browser.yandex.com", "api.browser.yandex.ru", "api.events.plus.yandex.net", 
    "api.expf.ru", "api.max.ru", "api.mindbox.ru", "api.ok.ru",
    "api.photo.2gis.com", "api.plus.kinopoisk.ru", "api.predict.mail.ru",
    "api.reviews.2gis.com", "api.s3.yandex.net", "api.uxfeedback.yandex.net",
    "api2.ivi.ru", "apps.research.mail.ru", "authdl.mail.ru", "auto.mail.ru",
    "auto.ru", "autodiscover.corp.mail.ru", "autodiscover.ord.ozon.ru", "av.mail.ru",
    "avatars.mds.yandex.com", "avatars.mds.yandex.net", "avito.ru", "avito.st", "aw.mail.ru",
    "azt.mail.ru", "b.auth-nsdi.ru", "b.res-nsdi.ru",
    "bank.ozon.ru", "banners-website.wildberries.ru", "bb.mail.ru", "bd.mail.ru",
    "beeline.api.flocktory.com", "beko.dom.mail.ru", "bender.mail.ru", "beta.mail.ru",
    "bitva.mail.ru", "biz.mail.ru", "blackfriday.mail.ru", "blog.mail.ru",
    "bot.gosuslugi.ru", "botapi.max.ru", "bratva-mr.mail.ru", "bro-bg-store.s3.yandex.com",
    "bro-bg-store.s3.yandex.net", "bro-bg-store.s3.yandex.ru", "brontp-pre.yandex.ru",
    "browser.mail.ru", "browser.yandex.com", "browser.yandex.ru",
    "c.dns-shop.ru", "c.rdrom.ru", "calendar.mail.ru", "capsula.mail.ru", "cargo.rzd.ru",
    "cars.mail.ru", "catalog.api.2gis.com", "cdn.connect.mail.ru", "cdn.gpb.ru",
    "cdn.lemanapro.ru", "cdn.newyear.mail.ru", "cdn.rosbank.ru", "cdn.s3.yandex.net",
    "cdn.uxfeedback.ru", "cdn.yandex.ru", "cdn1.tu-tu.ru", "cdnn21.img.ria.ru",
    "cdnrhkgfkkpupuotntfj.svc.cdn.yandex.net", "cf.mail.ru", "chat-ct.pochta.ru",
    "chat-prod.wildberries.ru", "cloud.cdn.yandex.com", "cloud.cdn.yandex.net",
    "cloud.cdn.yandex.ru", "cloud.mail.ru", "cloudcdn-ams19.cdn.yandex.net", 
    "cloudcdn-m9-10.cdn.yandex.net", "cloudcdn-m9-12.cdn.yandex.net", 
    "cloudcdn-m9-13.cdn.yandex.net", "cloudcdn-m9-14.cdn.yandex.net", 
    "cloudcdn-m9-15.cdn.yandex.net", "cloudcdn-m9-2.cdn.yandex.net", 
    "cloudcdn-m9-3.cdn.yandex.net", "cloudcdn-m9-4.cdn.yandex.net", 
    "cloudcdn-m9-5.cdn.yandex.net", "cloudcdn-m9-6.cdn.yandex.net", 
    "cloudcdn-m9-7.cdn.yandex.net", "cloudcdn-m9-9.cdn.yandex.net", "cm.a.mts.ru",
    "cobma.mail.ru", "cobmo.mail.ru", "code.mail.ru",
    "codefest.mail.ru", "cog.mail.ru", "collections.yandex.com", "collections.yandex.ru",
    "comba.mail.ru", "combu.mail.ru", "commba.mail.ru", "company.rzd.ru", "compute.mail.ru",
    "contacts.rzd.ru", "contract.gosuslugi.ru", "corp.mail.ru",
    "counter.yadro.ru", "cpa.hh.ru", "cpg.money.mail.ru", "crazypanda.mail.ru",
    "crowdtest.payment-widget-smarttv.plus.tst.kinopoisk.ru",
    "crowdtest.payment-widget.plus.tst.kinopoisk.ru", "cs.avito.ru",
    "csp.yandex.net", "ctlog.mail.ru", "ctlog2023.mail.ru", "ctlog2024.mail.ru", "cto.mail.ru",
    "cups.mail.ru", "d-assets.2gis.ru", "d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net",
    "da-preprod.biz.mail.ru", "da.biz.mail.ru", "data.amigo.mail.ru", "dating.ok.ru",
    "deti.mail.ru", "dev.max.ru", "dev1.mail.ru",
    "dev2.mail.ru", "dev3.mail.ru", "digital.gov.ru", "disk.2gis.com", "disk.rzd.ru",
    "dk.mail.ru", "dl.mail.ru", "dl.marusia.mail.ru", "dmp.dmpkit.lemanapro.ru", "dn.mail.ru",
    "dnd.wb.ru", "dobro.mail.ru", "doc.mail.ru", "dom.mail.ru", "download.max.ru",
    "dr.yandex.net", "dr2.yandex.net", "dragonpals.mail.ru", "ds.mail.ru", "duck.mail.ru",
    "duma.gov.ru", "dzen.ru", "e.mail.ru", "education.mail.ru", "egress.yandex.net",
    "ekmp-a-51.rzd.ru", "enterprise.api-maps.yandex.ru", "epp.genproc.gov.ru",
    "esc.predict.mail.ru", "esia.gosuslugi.ru", "et.mail.ru",
    "external-api.mediabilling.kinopoisk.ru", "external-api.plus.kinopoisk.ru",
    "eye.targetads.io", "favicon.yandex.com", "favicon.yandex.net", "favicon.yandex.ru",
    "favorites.api.2gis.com", "fb-cdn.premier.one", "fe.mail.ru", "filekeeper-vod.2gis.com",
    "finance.mail.ru", "finance.wb.ru", "five.predict.mail.ru", "foto.mail.ru",
    "frontend.vh.yandex.ru", "fw.wb.ru", "games-bamboo.mail.ru", "games-fisheye.mail.ru",
    "games.mail.ru", "gazeta.ru", "genesis.mail.ru", "geo-apart.predict.mail.ru",
    "get4click.ru", "gibdd.mail.ru", "go.mail.ru", "golos.mail.ru", "gosuslugi.ru",
    "gosweb.gosuslugi.ru", "government.ru", "goya.rutube.ru", "gpb.finance.mail.ru",
    "graphql-web.kinopoisk.ru", "graphql.kinopoisk.ru", "gu-st.ru", "guns.mail.ru",
    "hb-bidder.skcrtxr.com", "hd.kinopoisk.ru", "health.mail.ru", "help.max.ru",
    "help.mcs.mail.ru", "hh.ru", "hhcdn.ru", "hi-tech.mail.ru", "horo.mail.ru",
    "hs.mail.ru", "http-check-headers.yandex.ru", "i.hh.ru", "i.max.ru", "i.rdrom.ru",
    "i0.photo.2gis.com", "i1.photo.2gis.com", "i2.photo.2gis.com", "i3.photo.2gis.com",
    "i4.photo.2gis.com", "i5.photo.2gis.com", "i6.photo.2gis.com", "i7.photo.2gis.com",
    "i8.photo.2gis.com", "i9.photo.2gis.com", "identitystatic.mts.ru", "images.apteka.ru",
    "imgproxy.cdn-tinkoff.ru", "imperia.mail.ru", "informer.yandex.ru", "infra.mail.ru",
    "internet.mail.ru", "invest.ozon.ru", "io.ozone.ru", "ir.ozone.ru", "it.mail.ru",
    "izbirkom.ru", "jam.api.2gis.com", "jd.mail.ru", "jitsi.wb.ru", "journey.mail.ru",
    "jsons.injector.3ebra.net", "juggermobile.mail.ru", "junior.mail.ru", "keys.api.2gis.com",
    "kicker.mail.ru", "kiks.yandex.com", "kiks.yandex.ru", "kingdomrift.mail.ru",
    "kino.mail.ru", "knights.mail.ru", "kobma.mail.ru", "kobmo.mail.ru", "komba.mail.ru",
    "kombo.mail.ru", "kombu.mail.ru", "kommba.mail.ru", "konflikt.mail.ru", "kp.ru",
    "kremlin.ru", "kz.mcs.mail.ru", "la.mail.ru", "lady.mail.ru", "landing.mail.ru",
    "learning.ozon.ru", "legal.max.ru", "legenda.mail.ru",
    "legendofheroes.mail.ru", "lemanapro.ru", "lenta.ru", "link.max.ru", "link.mp.rzd.ru",
    "live.ok.ru", "lk.gosuslugi.ru", "loa.mail.ru", "log.strm.yandex.ru",
    "login.mts.ru", "lotro.mail.ru", "love.mail.ru", "m.47news.ru", "m.avito.ru", "m.ok.ru",
    "ma.kinopoisk.ru", "magnit-ru.injector.3ebra.net",
    "mail.yandex.com", "mail.yandex.ru", "mailer.mail.ru", "mailexpress.mail.ru",
    "man.mail.ru", "map.gosuslugi.ru", "mapgl.2gis.com", "mapi.learning.ozon.ru",
    "maps.mail.ru", "market.rzd.ru", "marusia.mail.ru", "max.ru", "mc.yandex.com",
    "mc.yandex.ru", "mcs.mail.ru", "mddc.tinkoff.ru", "media-golos.mail.ru",
    "media.mail.ru", "mediafeeds.yandex.com", "mediafeeds.yandex.ru", "mediapro.mail.ru",
    "merch-cpg.money.mail.ru", "metrics.alfabank.ru", "microapps.kinopoisk.ru",
    "miniapp.internal.myteam.mail.ru", "minigames.mail.ru", "mkb.ru", "mking.mail.ru",
    "mobfarm.mail.ru", "money.mail.ru", "moscow.megafon.ru", "moskva.beeline.ru",
    "moskva.taximaxim.ru", "mosqa.mail.ru", "mowar.mail.ru", "mozilla.mail.ru", "mp.rzd.ru",
    "msk.t2.ru", "mtscdn.ru", "multitest.ok.ru", "my.mail.ru", "my.rzd.ru", "myteam.mail.ru", 
    "nebogame.mail.ru", "net.mail.ru", "neuro.translate.yandex.ru", "new.mail.ru", 
    "news.mail.ru", "newyear.mail.ru", "newyear2018.mail.ru", "nonstandard.sales.mail.ru", 
    "notes.mail.ru", "novorossiya.gosuslugi.ru", "nspk.ru", "octavius.mail.ru", "ok.ru", 
    "oneclick-payment.kinopoisk.ru", "operator.mail.ru", "ord.ozon.ru", "otvet.mail.ru",
    "otveti.mail.ru", "otvety.mail.ru", "owa.ozon.ru", "ozon.ru", "ozone.ru", "panzar.mail.ru",
    "park.mail.ru", "partners.gosuslugi.ru", "partners.lemanapro.ru", "passport.pochta.ru",
    "pay.mail.ru", "pay.ozon.ru", "payment-widget-smarttv.plus.kinopoisk.ru",
    "payment-widget.kinopoisk.ru", "payment-widget.plus.kinopoisk.ru", "pernatsk.mail.ru",
    "personalization-web-stable.mindbox.ru", "pets.mail.ru", "pic.rutubelist.ru", "pikabu.ru",
    "pms.mail.ru", "pochta.ru", "pochtabank.mail.ru",
    "pogoda.mail.ru", "pokerist.mail.ru", "polis.mail.ru", "pos.gosuslugi.ru", "pp.mail.ru",
    "predict.mail.ru", "preview.rutube.ru", "primeworld.mail.ru",
    "privacy-cs.mail.ru", "prodvizhenie.rzd.ru", "ptd.predict.mail.ru", "pubg.mail.ru",
    "public-api.reviews.2gis.com", "public.infra.mail.ru", "pulse.mail.ru", "pulse.mp.rzd.ru",
    "pw.mail.ru", "px.adhigh.net", "quantum.mail.ru",
    "quiz.kinopoisk.ru", "r0.mradx.net", "rambler.ru", "rap.skcrtxr.com",
    "rate.mail.ru", "rbc.ru", "rebus.calls.mail.ru", "rebus.octavius.mail.ru",
    "receive-sentry.lmru.tech", "reseach.mail.ru", "restapi.dns-shop.ru", "rev.mail.ru",
    "riot.mail.ru", "rl.mail.ru", "rm.mail.ru", "rs.mail.ru", "rt.api.operator.mail.ru",
    "rutube.ru", "rzd.ru", "s.rbk.ru", "s0.bss.2gis.com", "s1.bss.2gis.com",
    "s11.auto.drom.ru", "s3.babel.mail.ru", "s3.mail.ru", "s3.media-mobs.mail.ru", "s3.t2.ru",
    "s3.yandex.net", "sales.mail.ru", "sangels.mail.ru", "sba.yandex.com", "sba.yandex.net",
    "sba.yandex.ru", "scitylana.apteka.ru", "sdk.money.mail.ru",
    "secure-cloud.rzd.ru", "secure.rzd.ru", "securepay.ozon.ru", "security.mail.ru",
    "seller.ozon.ru", "sentry.hh.ru", "service.amigo.mail.ru", "servicepipe.ru",
    "serving.a.mts.ru", "sfd.gosuslugi.ru", "shadowbound.mail.ru", "sntr.avito.ru",
    "socdwar.mail.ru", "sochi-park.predict.mail.ru", "souz.mail.ru", "speller.yandex.net",
    "sphere.mail.ru", "splitter.wb.ru", "sport.mail.ru",
    "sso.auto.ru", "sso.dzen.ru", "sso.kinopoisk.ru", "ssp.rutube.ru", "st-gismeteo.st",
    "st-im.kinopoisk.ru", "st.avito.ru", "st.gismeteo.st",
    "st.kinopoisk.ru", "st.max.ru", "st.okcdn.ru", "st.ozone.ru",
    "staging-analytics.predict.mail.ru", "staging-esc.predict.mail.ru",
    "staging-sochi-park.predict.mail.ru", "stand.aoc.mail.ru", "stand.bb.mail.ru",
    "stand.cb.mail.ru", "stand.la.mail.ru", "stand.pw.mail.ru", "startrek.mail.ru",
    "stat-api.gismeteo.net", "statad.ru", "static-mon.yandex.net", "static.apteka.ru",
    "static.beeline.ru", "static.dl.mail.ru", "static.lemanapro.ru", "static.operator.mail.ru",
    "static.rutube.ru", "stats.avito.ru", "status.mcs.mail.ru",
    "storage.ape.yandex.net", "storage.yandexcloud.net", "stormriders.mail.ru",
    "stream.mail.ru", "street-combats.mail.ru", "strm-rad-23.strm.yandex.net",
    "strm-spbmiran-07.strm.yandex.net", "strm-spbmiran-08.strm.yandex.net", "strm.yandex.net",
    "strm.yandex.ru", "styles.api.2gis.com", "suggest.dzen.ru", "suggest.sso.dzen.ru",
    "support.biz.mail.ru", "support.mcs.mail.ru", "support.tech.mail.ru", "surveys.yandex.ru",
    "sync.browser.yandex.net", "sync.rambler.ru", "tag.a.mts.ru", "tamtam.ok.ru",
    "target.smi2.net", "team.mail.ru", "team.rzd.ru", "tech.mail.ru",
    "tera.mail.ru", "ticket.rzd.ru", "tickets.widget.kinopoisk.ru",
    "tidaltrek.mail.ru", "tile0.maps.2gis.com", "tile1.maps.2gis.com", "tile2.maps.2gis.com",
    "tile3.maps.2gis.com", "tile4.maps.2gis.com", "tiles.maps.mail.ru", "tmgame.mail.ru",
    "tns-counter.ru", "todo.mail.ru", "top-fwz1.mail.ru",
    "touch.kinopoisk.ru", "townwars.mail.ru", "travel.rzd.ru", "travel.yandex.ru",
    "travel.yastatic.net", "trk.mail.ru", "ttbh.mail.ru", "tutu.ru", "tv.mail.ru",
    "typewriter.mail.ru", "u.corp.mail.ru", "ufo.mail.ru",
    "user-geo-data.wildberries.ru", "uslugi.yandex.ru", "uxfeedback-cdn.s3.yandex.net",
    "uxfeedback.yandex.ru", "voina.mail.ru", "voter.gosuslugi.ru", "vt-1.ozone.ru",
    "wap.yandex.com", "wap.yandex.ru", "warface.mail.ru", "warheaven.mail.ru",
    "wartune.mail.ru", "wb.ru", "wcm.weborama-tech.ru", "web-static.mindbox.ru", "web.max.ru",
    "webagent.mail.ru", "weblink.predict.mail.ru", "webstore.mail.ru", "welcome.mail.ru",
    "welcome.rzd.ru", "wf.mail.ru", "wh-cpg.money.mail.ru", "whatsnew.mail.ru",
    "widgets.kinopoisk.ru", "wok.mail.ru", "wos.mail.ru",
    "ws-api.oneme.ru", "ws.seller.ozon.ru", "www.avito.ru", "www.avito.st", "www.biz.mail.ru",
    "www.cikrf.ru", "www.drive2.ru", "www.drom.ru", "www.farpost.ru", "www.gazprombank.ru",
    "www.gosuslugi.ru", "www.ivi.ru", "www.kinopoisk.ru", "www.kp.ru", "www.magnit.com",
    "www.mail.ru", "www.mcs.mail.ru", "www.open.ru", "www.ozon.ru", "www.pochta.ru",
    "www.psbank.ru", "www.pubg.mail.ru", "www.raiffeisen.ru", "www.rbc.ru", "www.rzd.ru",
    "www.t2.ru", "www.tutu.ru", "www.unicreditbank.ru",
    "www.wf.mail.ru", "www.wildberries.ru", "www.x5.ru", "xapi.ozon.ru",
    "xn--80ajghhoc2aj1c8b.xn--p1ai", "ya.ru", "yabro-wbplugin.edadeal.yandex.ru",
    "yabs.yandex.ru", "yandex.com", "yandex.net", "yandex.ru", "yastatic.net", "yummy.drom.ru",
    "zen-yabro-morda.mediascope.mc.yandex.ru", "zen.yandex.com", "zen.yandex.net",
    "zen.yandex.ru", "честныйзнак.рф"
]

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")
sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in SNI_DOMAINS) + r")")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

def get_remote_urls():
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=10)
        resp.raise_for_status()
        urls_block = re.search(r'URLS\s*=\s*\[(.*?)\]', resp.text, re.DOTALL)
        if urls_block:
            content = urls_block.group(1)
            found = re.findall(r'https?://[^\s"\',]+', content)
            urls = list(set([u.strip() for u in found]))
            print(f"🔗 Успешно подтянуто источников: {len(urls)}")
            return urls
        return []
    except Exception as e:
        print(f"⚠️ Ошибка при чтении мастер-файла: {e}")
        return []

def fetch_and_filter(url):
    """Сбор конфигов с фильтрацией по SNI и исключение RU-локаций"""
    BANNED_WORDS = ["RU", "RUSSIA", "РОССИЯ", "🇷🇺"]
    try:
        resp = requests.get(url, timeout=15, verify=False)
        resp.raise_for_status()
        
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS):
                continue
            if not sni_regex.search(line):
                continue
            if "#" in line:
                name_part = line.split("#")[-1].upper()
                if any(word.upper() in name_part for word in BANNED_WORDS):
                    continue
            valid.append(line)
        return valid
    except:
        return []

def update_readme(count):
    content = f"# VPN Configs (Synced)\n\nОбновлено (МСК): **{offset}**\nКонфигов: **{count}**\n\n### Файл:\n`https://github.com/{REPO_NAME}/raw/refs/heads/main/githubmirror/vlm`"
    try:
        readme = REPO.get_contents("README.md")
        REPO.update_file(readme.path, "📝 Sync README", content, readme.sha)
    except:
        REPO.create_file("README.md", "🆕 Create README", content)

def main():
    remote_urls = get_remote_urls()
    print(f"🔗 Найдено источников: {len(remote_urls)}")

    all_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_and_filter, url) for url in remote_urls]
        for f in concurrent.futures.as_completed(futures):
            all_configs.extend(f.result())

    unique_configs = list(set(all_configs))
    
    # Ограничение до 450 штук
    if len(unique_configs) > 450:
        print(f"✂️ Найдено {len(unique_configs)} конфигов. Обрезаем до 450.")
        unique_configs = unique_configs[:450]

    unique_data = "\n".join(unique_configs)
    
    path = f"githubmirror/{FINAL_FILENAME}"
    try:
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync vlm | {offset}", unique_data, curr.sha)
        except:
            REPO.create_file(path, f"🆕 Create vlm | {offset}", unique_data)
        print(f"✅ Готово. Сохранено конфигов: {len(unique_configs)}")
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")

    update_readme(len(unique_configs))

if __name__ == "__main__":
    main()
