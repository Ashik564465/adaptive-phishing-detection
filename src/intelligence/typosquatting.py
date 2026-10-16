import tldextract
from src.intelligence.brand_engine import analyze_brand
from src.intelligence.url_normalizer import normalize_url


# ============================================================
# Known official brand domains
# ============================================================
BRAND_DOMAINS = {

    # ============================================================
    # GOOGLE / MICROSOFT / APPLE / GLOBAL TECHNOLOGY
    # ============================================================

    "google": {
        "google.com",
        "google.co.in",
        "gmail.com",
        "googlemail.com",
        "youtube.com",
        "youtu.be",
        "googleusercontent.com",
        "googleapis.com",
        "gstatic.com",
        "googleadservices.com",
        "googlesyndication.com",
        "googlevideo.com",
        "android.com",
        "android.google.com",
        "chrome.com",
    },

    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "outlook.live.com",
        "hotmail.com",
        "msn.com",
        "azure.com",
        "windows.com",
        "windows.net",
        "visualstudio.com",
        "xbox.com",
        "onedrive.com",
        "sharepoint.com",
        "teams.microsoft.com",
    },

    "apple": {
        "apple.com",
        "icloud.com",
        "appleid.apple.com",
        "itunes.com",
        "itunes.apple.com",
        "appstore.com",
        "developer.apple.com",
    },

    "amazon": {
        "amazon.com",
        "amazon.in",
        "amazon.co.uk",
        "amazon.de",
        "amazon.fr",
        "amazon.ca",
        "amazon.com.au",
        "amazon.co.jp",
        "amazonaws.com",
        "aws.amazon.com",
        "aws.amazon.com",
        "primevideo.com",
        "amazonpay.in",
        "amazonpay.com",
    },

    # ============================================================
    # SOCIAL MEDIA
    # ============================================================

    "facebook": {
        "facebook.com",
        "facebook.net",
        "fb.com",
        "fb.me",
        "messenger.com",
        "meta.com",
        "meta.ai",
    },

    "instagram": {
        "instagram.com",
        "cdninstagram.com",
    },

    "whatsapp": {
        "whatsapp.com",
        "whatsapp.net",
    },

    "telegram": {
        "telegram.org",
        "t.me",
        "telegra.ph",
    },

    "linkedin": {
        "linkedin.com",
        "linkedin.co.in",
        "licdn.com",
    },

    "twitter_x": {
        "twitter.com",
        "x.com",
        "t.co",
        "twimg.com",
    },

    "reddit": {
        "reddit.com",
        "redditmedia.com",
        "redd.it",
    },

    "discord": {
        "discord.com",
        "discordapp.com",
        "discord.gg",
    },

    "snapchat": {
        "snapchat.com",
        "snap.com",
    },

    "pinterest": {
        "pinterest.com",
        "pinimg.com",
    },

    "tiktok": {
        "tiktok.com",
        "tiktokcdn.com",
        "musical.ly",
    },

    "quora": {
        "quora.com",
        "quora.com",
    },

    "threads": {
        "threads.net",
    },

    # ============================================================
    # MAJOR GLOBAL FINANCIAL BRANDS
    # ============================================================

    "paypal": {
        "paypal.com",
        "paypal.me",
        "paypalobjects.com",
    },

    "stripe": {
        "stripe.com",
        "stripe.network",
        "stripe.dev",
    },

    "visa": {
        "visa.com",
        "visa.co.in",
        "visa.co.uk",
    },

    "mastercard": {
        "mastercard.com",
        "mastercard.co.in",
    },

    "american_express": {
        "americanexpress.com",
        "amex.com",
    },

    "western_union": {
        "westernunion.com",
        "westernunionindia.in",
    },

    "moneygram": {
        "moneygram.com",
    },

    "wise": {
        "wise.com",
    },

    "revolut": {
        "revolut.com",
    },

    "coinbase": {
        "coinbase.com",
        "coinbaseusercontent.com",
    },

    "binance": {
        "binance.com",
        "binance.us",
        "binance.info",
    },

    "kraken": {
        "kraken.com",
    },

    # ============================================================
    # INDIAN PUBLIC SECTOR BANKS
    # ============================================================

    "sbi": {
        "sbi.co.in",
        "sbi.bank.in",
        "bank.sbi",
        "onlinesbi.sbi",
        "onlinesbi.com",
    },

    "bank_of_baroda": {
        "bankofbaroda.in",
        "bankofbaroda.co.in",
        "bankofbaroda.com",
        "bankofbaroda.bank.in",
    },

    "bank_of_india": {
        "bankofindia.co.in",
        "bankofindia.com",
        "bankofindia.bank.in",
    },

    "bank_of_maharashtra": {
        "bankofmaharashtra.in",
        "bankofmaharashtra.co.in",
        "bankofmaharashtra.com",
        "bankofmaharashtra.bank.in",
    },

    "canara_bank": {
        "canarabank.com",
        "canarabank.in",
        "canarabank.co.in",
        "canarabank.bank.in",
    },

    "central_bank_of_india": {
        "centralbankofindia.co.in",
        "centralbankofindia.com",
        "centralbank.bank.in",
    },

    "indian_bank": {
        "indianbank.in",
        "indianbank.co.in",
        "indianbank.com",
        "indianbank.bank.in",
    },

    "indian_overseas_bank": {
        "iob.in",
        "iob.bank.in",
    },

    "punjab_national_bank": {
        "pnbindia.in",
        "pnbindia.co.in",
        "pnbindia.com",
        "pnb.bank.in",
    },

    "punjab_sind_bank": {
        "punjabandsindbank.co.in",
        "punjabandsindbank.in",
        "psbindia.com",
        "psb.bank.in",
    },

    "uco_bank": {
        "ucobank.com",
        "ucobank.in",
        "uco.bank.in",
    },

    "union_bank": {
        "unionbankofindia.co.in",
        "unionbankofindia.in",
        "unionbankofindia.bank.in",
        "unionbankonline.co.in",
    },

    # ============================================================
    # INDIAN PRIVATE BANKS
    # ============================================================

    "hdfc": {
        "hdfcbank.com",
        "hdfc.bank.in",
        "hdfc.com",
        "hdfclife.com",
        "hdfcergo.com",
    },

    "icici": {
        "icicibank.com",
        "icici.bank.in",
        "icici.com",
        "icicilombard.com",
        "iciciprulife.com",
    },

    "axis": {
        "axisbank.com",
        "axis.bank.in",
        "axis.com",
        "axisdirect.in",
        "axisdirect.com",
    },

    "kotak": {
        "kotak.com",
        "kotak.bank.in",
        "kotakmahindra.com",
        "kotaksecurities.com",
        "kotaklife.com",
    },

    "indusind": {
        "indusind.com",
        "indusind.bank.in",
        "indusindbank.com",
    },

    "idfc_first": {
        "idfcfirstbank.com",
        "idfcfirst.bank.in",
        "idfcfirstbank.in",
        "idfcfirst.com",
    },

    "idbi": {
        "idbibank.in",
        "idbibank.co.in",
        "idbi.bank.in",
    },

    "yes_bank": {
        "yesbank.in",
        "yes.bank.in",
        "yesbank.com",
    },

    "federal_bank": {
        "federalbank.co.in",
        "federalbank.in",
        "federal.bank.in",
    },

    "rbl": {
        "rblbank.com",
        "rbl.bank.in",
        "rblbank.in",
    },

    "bandhan": {
        "bandhanbank.com",
        "bandhan.bank.in",
        "bandhanbank.in",
    },

    "south_indian_bank": {
        "southindianbank.com",
        "southindianbank.in",
        "southindianbank.bank.in",
    },

    "karnataka_bank": {
        "karnatakabank.com",
        "karnatakabank.in",
        "karnatakabank.bank.in",
    },

    "karur_vysya_bank": {
        "kvb.co.in",
        "kvb.bank.in",
        "karurvysyabank.co.in",
    },

    "tamilnad_mercantile_bank": {
        "tmbnet.in",
        "tmb.bank.in",
        "tmb.in",
        "tmbank.in",
    },

    "city_union_bank": {
        "cityunionbank.com",
        "cityunionbank.in",
        "cityunionbank.bank.in",
    },

    "dhanlaxmi_bank": {
        "dhanbank.com",
        "dhan.bank.in",
    },

    "csb_bank": {
        "csb.co.in",
        "csb.bank.in",
    },

    "dcb_bank": {
        "dcbbank.com",
        "dcb.bank.in",
    },

    "nainital_bank": {
        "nainitalbank.co.in",
        "nainitalbank.bank.in",
    },

    "jammu_kashmir_bank": {
        "jkb.com",
        "jkb.bank.in",
        "jkbank.com",
        "jkb.co.in",
    },

    # ============================================================
    # SMALL FINANCE BANKS
    # ============================================================

    "au_small_finance_bank": {
        "aubank.in",
        "au.bank.in",
        "aubank.com",
    },

    "ujjivan": {
        "ujjivansfb.in",
        "ujjivan.bank.in",
        "ujjivansfb.com",
    },

    "equitas": {
        "equitasbank.com",
        "equitas.bank.in",
        "equitas.in",
    },

    "jana": {
        "janabank.com",
        "jana.bank.in",
        "janabank.in",
    },

    "suryoday": {
        "suryodaybank.com",
        "suryoday.bank.in",
    },

    "esaf": {
        "esafbank.com",
        "esaf.bank.in",
    },

    "utkarsh": {
        "utkarsh.bank.in",
        "utkarshcoreinvest.com",
    },

    "north_east_small_finance": {
        "nesfb.com",
        "nesfb.bank.in",
    },

    "capital_small_finance": {
        "capitalbank.co.in",
        "capital.bank.in",
    },

    # ============================================================
    # PAYMENTS / UPI / FINTECH INDIA
    # ============================================================

    "upi": {
        "npci.org.in",
        "upi.org.in",
        "upi.npci.org.in",
    },

    "phonepe": {
        "phonepe.com",
        "phonepe.in",
    },

    "google_pay": {
        "pay.google.com",
        "googlepay.com",
        "gpay.app",
    },

    "paytm": {
        "paytm.com",
        "paytm.in",
        "paytmbank.com",
        "paytmbank.in",
    },

    "bharatpe": {
        "bharatpe.com",
        "bharatpe.in",
    },

    "mobikwik": {
        "mobikwik.com",
        "mobikwik.in",
    },

    "freecharge": {
        "freecharge.in",
        "freecharge.com",
    },

    "airtel_payments": {
        "airtel.in",
        "airtelpaymentsbank.com",
        "airtelpayments.bank.in",
    },

    "jio_finance": {
        "jio.com",
        "jiofinance.in",
    },

    "amazon_pay": {
        "amazonpay.in",
        "amazon.in",
    },

    "cred": {
        "cred.club",
        "cred.club",
    },

    "slice": {
        "sliceit.com",
        "slice.bank.in",
    },

    "fi": {
        "fi.money",
    },

    "jupiter": {
        "jupiter.money",
    },

    "niyo": {
        "niyopay.com",
        "goniyo.com",
    },

    "razorpay": {
        "razorpay.com",
        "razorpay.in",
    },

    "cashfree": {
        "cashfree.com",
        "cashfreepayments.com",
    },

    "payu": {
        "payu.in",
        "payu.com",
    },

    "billdesk": {
        "billdesk.com",
    },

    # ============================================================
    # INDIAN STOCK / INVESTMENT PLATFORMS
    # ============================================================

    "zerodha": {
        "zerodha.com",
        "zerodha.net",
    },

    "groww": {
        "groww.in",
        "groww.com",
    },

    "upstox": {
        "upstox.com",
        "upstox.in",
    },

    "angel_one": {
        "angelone.in",
        "angelbroking.com",
    },

    "motilal_oswal": {
        "motilaloswal.com",
        "motilaloswal.in",
    },

    "5paisa": {
        "5paisa.com",
    },

    "icici_direct": {
        "icicidirect.com",
        "icicidirect.in",
    },

    "hdfc_securities": {
        "hdfcsec.com",
        "hdfcsec.in",
    },

    "kotak_securities": {
        "kotaksecurities.com",
        "kotakneo.com",
    },

    "iifl": {
        "iifl.com",
        "indiainfoline.com",
    },

    "edelweiss": {
        "edelweiss.in",
        "edelweissmf.com",
    },

    # ============================================================
    # INSURANCE / LIC
    # ============================================================

    "lic": {
        "licindia.in",
        "licindia.com",
        "licindia.in",
    },

    "sbi_life": {
        "sbilife.co.in",
        "sbilife.com",
    },

    "hdfc_life": {
        "hdfclife.com",
        "hdfclife.in",
    },

    "icici_prudential": {
        "iciciprulife.com",
        "iciciprulife.in",
    },

    "max_life": {
        "maxlifeinsurance.com",
        "maxlifeinsurance.in",
    },

    "tata_aia": {
        "tataaia.com",
        "tataaia.in",
    },

    "bajaj_allianz": {
        "bajajallianzlife.com",
        "bajajallianz.com",
    },

    "star_health": {
        "starhealth.in",
        "starhealthinsurance.com",
    },

    "care_health": {
        "careinsurance.com",
        "careinsurance.in",
    },

    "niva_bupa": {
        "nivabupa.com",
        "nivabupa.in",
    },

    "new_india_assurance": {
        "newindia.co.in",
        "newindia.com",
    },

    # ============================================================
    # TELECOM
    # ============================================================

    "airtel": {
        "airtel.in",
        "airtel.com",
    },

    "jio": {
        "jio.com",
        "jio.in",
    },

    "vi": {
        "myvi.in",
        "vodafoneidea.com",
        "vi.in",
    },

    "bsnl": {
        "bsnl.co.in",
        "bsnl.in",
    },

    "mtnl": {
        "mtnl.net.in",
        "mtnl.in",
    },

    # ============================================================
    # INDIAN ECOMMERCE
    # ============================================================

    "flipkart": {
        "flipkart.com",
        "flipkart.net",
        "flipkart.in",
    },

    "myntra": {
        "myntra.com",
        "myntra.in",
    },

    "meesho": {
        "meesho.com",
        "meesho.io",
    },

    "ajio": {
        "ajio.com",
        "ajio.in",
    },

    "snapdeal": {
        "snapdeal.com",
        "snapdeal.in",
    },

    "nykaa": {
        "nykaa.com",
        "nykaa.in",
    },

    "tatacliq": {
        "tatacliq.com",
        "tatacliq.in",
    },

    "reliance_digital": {
        "reliancedigital.in",
        "reliancedigital.com",
    },

    "croma": {
        "croma.com",
        "croma.in",
    },

    "firstcry": {
        "firstcry.com",
        "firstcry.in",
    },

    "bigbasket": {
        "bigbasket.com",
        "bigbasket.in",
    },

    "blinkit": {
        "blinkit.com",
        "blinkit.in",
    },

    "zepto": {
        "zeptonow.com",
        "zepto.in",
    },

    "swiggy": {
        "swiggy.com",
        "swiggy.in",
    },

    "zomato": {
        "zomato.com",
        "zomato.in",
    },

    "dominos": {
        "dominos.co.in",
        "dominos.com",
    },

    "mcdonalds": {
        "mcdonalds.com",
        "mcdelivery.co.in",
    },

    "kfc": {
        "kfc.co.in",
        "kfc.com",
    },

    # ============================================================
    # TRAVEL / TRANSPORT
    # ============================================================

    "irctc": {
        "irctc.co.in",
        "irctc.com",
        "irctc.co",
    },

    "indian_railways": {
        "indianrail.gov.in",
        "indianrailways.gov.in",
    },

    "redbus": {
        "redbus.in",
        "redbus.com",
    },

    "makemytrip": {
        "makemytrip.com",
        "makemytrip.in",
    },

    "goibibo": {
        "goibibo.com",
        "goibibo.in",
    },

    "cleartrip": {
        "cleartrip.com",
        "cleartrip.in",
    },

    "ixigo": {
        "ixigo.com",
        "ixigo.in",
    },

    "easemytrip": {
        "easemytrip.com",
        "easemytrip.in",
    },

    "air_india": {
        "airindia.com",
        "airindia.in",
    },

    "indigo": {
        "goindigo.in",
        "indigo.in",
    },

    "vistara": {
        "airvistara.com",
    },

    "spicejet": {
        "spicejet.com",
        "spicejet.in",
    },

    "akasa": {
        "akasaair.com",
        "akasaair.in",
    },

    "uber": {
        "uber.com",
        "uber.co.in",
    },

    "ola": {
        "olacabs.com",
        "olaelectric.com",
        "ola.in",
    },

    # ============================================================
    # GOVERNMENT / INDIA DIGITAL SERVICES
    # ============================================================

    "india_gov": {
        "india.gov.in",
        "mygov.in",
        "gov.in",
        "nic.in",
    },

    "incometax": {
        "incometax.gov.in",
        "incometaxindia.gov.in",
    },

    "gst": {
        "gst.gov.in",
        "gstn.org",
        "gst.gov.in",
    },

    "uidai": {
        "uidai.gov.in",
        "myaadhaar.uidai.gov.in",
    },

    "digilocker": {
        "digilocker.gov.in",
        "digitallocker.gov.in",
    },

    "passport": {
        "passportindia.gov.in",
        "passportindia.gov.in",
    },

    "epfo": {
        "epfindia.gov.in",
        "epfindia.nic.in",
    },

    "esic": {
        "esic.gov.in",
        "esic.nic.in",
    },

    "rbi": {
        "rbi.org.in",
        "rbi.in",
    },

    "sebi": {
        "sebi.gov.in",
        "sebi.org.in",
    },

    "irdai": {
        "irdai.gov.in",
    },

    "trai": {
        "trai.gov.in",
    },

    "npcI": {
        "npci.org.in",
        "npci.in",
    },

    "parivahan": {
        "parivahan.gov.in",
        "parivahan.gov.in",
    },

    "cowin": {
        "cowin.gov.in",
        "selfregistration.cowin.gov.in",
    },

    "umang": {
        "umang.gov.in",
        "web.umang.gov.in",
    },

    "e_courts": {
        "ecourts.gov.in",
        "services.ecourts.gov.in",
    },

    "digiyatra": {
        "digiyatra.com",
        "digiyatra.gov.in",
    },

    # ============================================================
    # JOB / EDUCATION
    # ============================================================

    "naukri": {
        "naukri.com",
        "naukrigulf.com",
    },

    "indeed": {
        "indeed.com",
        "in.indeed.com",
    },

    "foundit": {
        "foundit.in",
        "monsterindia.com",
    },

    "linkedin_jobs": {
        "linkedin.com",
    },

    "internshala": {
        "internshala.com",
        "internshala.co.in",
    },

    "unstop": {
        "unstop.com",
        "d2c.pw",
    },

    "coursera": {
        "coursera.org",
        "coursera.com",
    },

    "udemy": {
        "udemy.com",
        "udemycdn.com",
    },

    "edx": {
        "edx.org",
    },

    "skillshare": {
        "skillshare.com",
    },

    "simplilearn": {
        "simplilearn.com",
    },

    "upgrad": {
        "upgrad.com",
        "upgrad.in",
    },

    "byjus": {
        "byjus.com",
        "byjus.in",
    },

    "vedantu": {
        "vedantu.com",
        "vedantu.in",
    },

    "unacademy": {
        "unacademy.com",
        "unacademy.in",
    },

    "leetcode": {
        "leetcode.com",
    },

    "hackerrank": {
        "hackerrank.com",
    },

    "github": {
        "github.com",
        "github.io",
        "githubusercontent.com",
    },

    "gitlab": {
        "gitlab.com",
        "gitlab.io",
    },

    "bitbucket": {
        "bitbucket.org",
    },

    # ============================================================
    # STREAMING / ENTERTAINMENT
    # ============================================================

    "netflix": {
        "netflix.com",
        "netflix.net",
    },

    "prime_video": {
        "primevideo.com",
        "amazon.com",
    },

    "hotstar": {
        "hotstar.com",
        "jiohotstar.com",
        "hotstar.in",
    },

    "sonyliv": {
        "sonyliv.com",
        "sonyliv.in",
    },

    "zee5": {
        "zee5.com",
        "zee5.in",
    },

    "jiocinema": {
        "jiocinema.com",
        "jiocinema.in",
    },

    "spotify": {
        "spotify.com",
        "spotify.co.in",
    },

    "apple_music": {
        "music.apple.com",
    },

    "gaana": {
        "gaana.com",
        "gaana.in",
    },

    "wynk": {
        "wynk.in",
        "wynk.music",
    },

    # ============================================================
    # CLOUD / DEVELOPER SERVICES
    # ============================================================

    "aws": {
        "amazonaws.com",
        "aws.amazon.com",
        "awsstatic.com",
        "aws.dev",
    },

    "azure": {
        "azure.com",
        "azure.microsoft.com",
        "windowsazure.com",
        "azurewebsites.net",
    },

    "google_cloud": {
        "cloud.google.com",
        "googleapis.com",
        "gcp.com",
    },

    "oracle": {
        "oracle.com",
        "oraclecloud.com",
        "oraclecloudapps.com",
    },

    "ibm": {
        "ibm.com",
        "ibmcloud.com",
    },

    "salesforce": {
        "salesforce.com",
        "salesforce.org",
    },

    "adobe": {
        "adobe.com",
        "adobe.io",
        "adobelogin.com",
    },

    "canva": {
        "canva.com",
        "canva.co",
    },

    "zoom": {
        "zoom.us",
        "zoom.com",
    },

    "dropbox": {
        "dropbox.com",
        "dropboxusercontent.com",
    },

    "slack": {
        "slack.com",
        "slack-edge.com",
    },

    "notion": {
        "notion.so",
        "notion.site",
    },

    # ============================================================
    # OTHER MAJOR GLOBAL BRANDS
    # ============================================================

    "nike": {
        "nike.com",
        "nike.in",
    },

    "adidas": {
        "adidas.com",
        "adidas.co.in",
    },

    "puma": {
        "puma.com",
        "puma.in",
    },

    "microsoft_store": {
        "microsoft.com",
    },

    "samsung": {
        "samsung.com",
        "samsung.co.in",
    },

    "oneplus": {
        "oneplus.com",
        "oneplus.in",
    },

    "xiaomi": {
        "mi.com",
        "mi.co.in",
        "xiaomi.com",
    },

    "realme": {
        "realme.com",
        "realme.com/in",
    },

    "oppo": {
        "oppo.com",
        "oppo.com/in",
    },

    "vivo": {
        "vivo.com",
        "vivo.com/in",
    },

    "hp": {
        "hp.com",
        "hp.com/in",
    },

    "dell": {
        "dell.com",
        "dell.com/en-in",
    },

    "lenovo": {
        "lenovo.com",
        "lenovo.com/in",
    },

    "flipkart": {
        "flipkart.com",
        "flipkart.net",
    },

    "tata": {
        "tata.com",
        "tatamotors.com",
        "tatapower.com",
        "tatacapital.com",
        "tatadigital.com",
        "tataconsumer.com",
    },

    "reliance": {
        "ril.com",
        "reliance.com",
        "reliancedigital.in",
        "relianceindustries.com",
    },

    "infosys": {
        "infosys.com",
        "infosys.in",
    },

    "tcs": {
        "tcs.com",
        "tcs.in",
    },

    "wipro": {
        "wipro.com",
        "wipro.in",
    },

    "hcl": {
        "hcltech.com",
        "hcl.com",
    },

    "tech_mahindra": {
        "techmahindra.com",
        "techmahindra.in",
    },

    "accenture": {
        "accenture.com",
        "accenture.co.in",
    },

    "capgemini": {
        "capgemini.com",
        "capgemini.co.in",
    },

    "deloitte": {
        "deloitte.com",
        "deloitte.com/in",
    },

    "ey": {
        "ey.com",
        "ey.com/en_in",
    },

    "pwc": {
        "pwc.com",
        "pwc.in",
    },

    "kpmg": {
        "kpmg.com",
        "kpmg.com/in",
    },

    # ============================================================
    # FOOD / DELIVERY
    # ============================================================

    "swiggy_instamart": {
        "swiggy.com",
        "instamart.in",
    },

    "dominos_india": {
        "dominos.co.in",
    },

    "pizza_hut": {
        "pizzahut.co.in",
        "pizzahut.com",
    },

    "blinkit": {
        "blinkit.com",
    },

    "zepto": {
        "zeptonow.com",
    },

    "bigbasket": {
        "bigbasket.com",
    },

    "dunzo": {
        "dunzo.com",
        "dunzo.in",
    },

    # ============================================================
    # TAX / ACCOUNTING / BUSINESS
    # ============================================================

    "tally": {
        "tallysolutions.com",
        "tallysolutions.com",
    },

    "zoho": {
        "zoho.com",
        "zoho.in",
        "zohocorp.com",
    },

    "freshworks": {
        "freshworks.com",
        "freshworks.in",
    },

    "razorpay": {
        "razorpay.com",
    },

    "cleartax": {
        "cleartax.in",
        "cleartax.com",
    },

    "phonepe_business": {
        "phonepe.com",
    },

    # ============================================================
    # MORE INDIAN DIGITAL / CONSUMER SERVICES
    # ============================================================

    "jio_mart": {
        "jiomart.com",
        "jiomart.in",
    },

    "tata_neu": {
        "tataneu.com",
        "tataneu.in",
    },

    "tata_1mg": {
        "1mg.com",
        "tata1mg.com",
    },

    "pharmeasy": {
        "pharmeasy.in",
        "pharmeasy.com",
    },

    "apollo": {
        "apollo247.com",
        "apollohospitals.com",
    },

    "practo": {
        "practo.com",
        "practo.in",
    },

    "cultfit": {
        "cult.fit",
        "cultfit.in",
    },

    "bookmyshow": {
        "bookmyshow.com",
        "bookmyshow.in",
    },

    "paytm_movies": {
        "paytm.com",
    },

    "olx": {
        "olx.in",
        "olx.com",
    },

    "quikr": {
        "quikr.com",
        "quikr.in",
    },

    "urban_company": {
        "urbancompany.com",
        "urbancompany.co.in",
    },

    "policybazaar": {
        "policybazaar.com",
        "policybazaar.in",
    },

    "paisabazaar": {
        "paisabazaar.com",
        "paisabazaar.in",
    },

    # ============================================================
    # INTERNATIONAL BANKS COMMONLY SEEN IN INDIA
    # ============================================================

    "hsbc": {
        "hsbc.com",
        "hsbc.co.in",
        "hsbc.bank.in",
    },

    "standard_chartered": {
        "sc.com",
        "sc.com/in",
    },

    "dbs": {
        "dbs.com",
        "dbs.bank.in",
        "dbs.com/in",
    },

    "citibank": {
        "citibank.com",
        "citibank.co.in",
    },

    "bank_of_america": {
        "bankofamerica.com",
    },

    "jpmorgan": {
        "jpmorgan.com",
        "jpmorganchase.com",
    },

    "barclays": {
        "barclays.com",
        "barclays.in",
    },

    "deutsche_bank": {
        "db.com",
        "deutschebank.co.in",
        "deutsche-bank.com",
    },

    "scotiabank": {
        "scotiabank.com",
    },

    # ============================================================
    # CRYPTO / WEB3
    # ============================================================

    "coindcx": {
        "coindcx.com",
        "coindcx.co",
    },

    "wazirx": {
        "wazirx.com",
        "wazirx.in",
    },

    "zebpay": {
        "zebpay.com",
        "zebpay.in",
    },

    "mudrex": {
        "mudrex.com",
        "mudrex.in",
    },

    "crypto_com": {
        "crypto.com",
    },

    # ============================================================
    # ADDITIONAL GLOBAL SERVICES
    # ============================================================

    "yahoo": {
        "yahoo.com",
        "yahoo.co.in",
        "yahoo.in",
    },

    "proton": {
        "proton.me",
        "protonmail.com",
        "protonvpn.com",
    },

    "duckduckgo": {
        "duckduckgo.com",
    },

    "cloudflare": {
        "cloudflare.com",
        "cloudflare.net",
    },

    "vercel": {
        "vercel.com",
        "vercel.app",
    },

    "netlify": {
        "netlify.com",
        "netlify.app",
    },

    "heroku": {
        "heroku.com",
        "herokuapp.com",
    },

    "digitalocean": {
        "digitalocean.com",
    },

    "databricks": {
        "databricks.com",
        "databricks.net",
    },

    "huggingface": {
        "huggingface.co",
    },

    "openai": {
        "openai.com",
        "chatgpt.com",
    },

    "anthropic": {
        "anthropic.com",
        "claude.ai",
    },

    "gemini": {
        "gemini.google.com",
    },

    "perplexity": {
        "perplexity.ai",
    },

    # ============================================================
    # RETAIL / CONSUMER
    # ============================================================

    "dmart": {
        "dmart.in",
        "avenuesupermarts.com",
    },

    "reliance_trends": {
        "reliancetrends.com",
    },

    "westside": {
        "westside.com",
        "trentlimited.com",
    },

    "decathlon": {
        "decathlon.in",
        "decathlon.com",
    },

    "lenskart": {
        "lenskart.com",
        "lenskart.in",
    },

    "titan": {
        "titan.co.in",
        "titancompany.in",
    },

    "fastrack": {
        "fastrack.in",
    },

    "mamaearth": {
        "mamaearth.in",
        "mamaearth.com",
    },

    "boat": {
        "boat-lifestyle.com",
        "boat-lifestyle.in",
    },

    "noise": {
        "gonoise.com",
        "gonoise.in",
    },

    "fire_boltt": {
        "fireboltt.com",
        "fireboltt.in",
    },

    # ============================================================
    # MEDIA / NEWS
    # ============================================================

    "times_of_india": {
        "timesofindia.indiatimes.com",
        "indiatimes.com",
    },

    "ndtv": {
        "ndtv.com",
        "ndtv.in",
    },

    "hindustan_times": {
        "hindustantimes.com",
        "ht.com",
    },

    "the_hindu": {
        "thehindu.com",
        "thehindu.co.in",
    },

    "india_today": {
        "indiatoday.in",
        "indiatoday.com",
    },

    "news18": {
        "news18.com",
        "news18.in",
    },

    "economic_times": {
        "economictimes.indiatimes.com",
        "economictimes.com",
    },

    "business_standard": {
        "business-standard.com",
    },

    "moneycontrol": {
        "moneycontrol.com",
        "moneycontrol.in",
    },

    # ============================================================
    # MISCELLANEOUS IMPORTANT DOMAINS
    # ============================================================

    "wikipedia": {
        "wikipedia.org",
        "wikimedia.org",
    },

    "mozilla": {
        "mozilla.org",
        "mozilla.com",
    },

    "firefox": {
        "mozilla.org",
    },

    "python": {
        "python.org",
        "python.com",
    },

    "npm": {
        "npmjs.com",
        "npmjs.org",
    },

    "docker": {
        "docker.com",
        "docker.io",
    },

    "kubernetes": {
        "kubernetes.io",
    },

    "jenkins": {
        "jenkins.io",
    },

    "stackoverflow": {
        "stackoverflow.com",
        "stackexchange.com",
    },

    "medium": {
        "medium.com",
    },

    "wordpress": {
        "wordpress.com",
        "wordpress.org",
    },

    "blogger": {
        "blogger.com",
        "blogspot.com",
    },

    "telegram_extra": {
        "telegram.me",
        "telegram.dog",
    },
}



# ============================================================
# Common character substitutions
# ============================================================

CHAR_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
}


# ============================================================
# Levenshtein distance
# ============================================================

def levenshtein_distance(a: str, b: str) -> int:

    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):

        current = [i]

        for j, char_b in enumerate(b, start=1):

            insertion = current[j - 1] + 1

            deletion = previous[j] + 1

            substitution = previous[j - 1] + (
                char_a != char_b
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution
                )
            )

        previous = current

    return previous[-1]


# ============================================================
# Normal similarity
# ============================================================

def similarity(a: str, b: str) -> float:

    if not a or not b:
        return 0.0

    a = a.lower()
    b = b.lower()

    distance = levenshtein_distance(a, b)

    max_length = max(
        len(a),
        len(b)
    )

    return 1.0 - (
        distance / max_length
    )


# ============================================================
# Normalize common character substitutions
#
# Example:
#
# g00gle -> google
# goog1e -> google
# micros0ft -> microsoft
# ============================================================

def normalize_confusable_chars(text: str) -> str:

    text = text.lower()

    return "".join(
        CHAR_SUBSTITUTIONS.get(
            char,
            char
        )
        for char in text
    )


# ============================================================
# Confusable similarity
# ============================================================

def confusable_similarity(
    domain_name: str,
    brand_name: str
) -> float:

    normalized_domain = (
        normalize_confusable_chars(
            domain_name
        )
    )

    return similarity(
        normalized_domain,
        brand_name
    )


# ============================================================
# Extract registered domain
# ============================================================

def get_registered_domain(url: str) -> str:
    return normalize_url(url)["registered_domain"]


# ============================================================
# Main typosquatting analysis
# ============================================================

def analyze_typosquatting(url: str):

    registered_domain = get_registered_domain(
        url
    )

    # --------------------------------------------------------
    # Invalid / empty domain
    # --------------------------------------------------------

    if not registered_domain:

        return {
            "registered_domain": "",
            "possible_typosquatting": False,
            "matched_brand": None,
            "similarity": 0.0,
            "confusable_similarity": 0.0,
            "attack_type": None,
        }

    # --------------------------------------------------------
    # Extract domain name
    # --------------------------------------------------------

    extracted = tldextract.extract(registered_domain)

    domain_name = extracted.domain.lower()

    # --------------------------------------------------------
    # Check whether this is already an official domain
    # --------------------------------------------------------

    exact_match = analyze_brand(url).get("official_domain") is True

    for official_domains in BRAND_DOMAINS.values():

        if registered_domain in official_domains:

            exact_match = True
            break

    # --------------------------------------------------------
    # Find closest brand
    # --------------------------------------------------------

    best_brand = None

    best_similarity = 0.0

    best_confusable_similarity = 0.0

    for brand, official_domains in BRAND_DOMAINS.items():

        for official_domain in official_domains:

            official_extracted = (
                tldextract.extract(
                    official_domain
                )
            )

            official_name = (
                official_extracted.domain.lower()
            )

            # Normal edit-distance similarity
            normal_score = similarity(
                domain_name,
                official_name
            )

            # Character-substitution similarity
            confusable_score = (
                confusable_similarity(
                    domain_name,
                    official_name
                )
            )

            # Keep the strongest score
            score = max(
                normal_score,
                confusable_score
            )

            if score > best_similarity:

                best_similarity = score

                best_confusable_similarity = (
                    confusable_score
                )

                best_brand = brand

    # ========================================================
    # Determine attack type
    # ========================================================

    possible_typosquatting = False

    attack_type = None

    # Official domains are never typosquatting
    if not exact_match:

        # ----------------------------------------------------
        # Character substitution
        #
        # Examples:
        # g00gle -> google
        # goog1e -> google
        # micros0ft -> microsoft
        # ----------------------------------------------------

        normalized_domain = (
            normalize_confusable_chars(
                domain_name
            )
        )

        has_character_substitution = (
            normalized_domain != domain_name
        )

        if (
            has_character_substitution
            and best_confusable_similarity >= 0.90
        ):

            possible_typosquatting = True

            attack_type = (
                "character_substitution"
            )

        # ----------------------------------------------------
        # Normal edit-distance attack
        #
        # Examples:
        # gooogle
        # gogle
        # googl
        # googlee
        # ----------------------------------------------------

        elif (
            best_similarity >= 0.80
            and best_similarity < 1.0
        ):

            possible_typosquatting = True

            attack_type = (
                "edit_distance"
            )

    # ========================================================
    # Return result
    # ========================================================

    return {
        "registered_domain": registered_domain,

        "possible_typosquatting": (
            possible_typosquatting
        ),

        "matched_brand": (
            best_brand
            if possible_typosquatting
            else None
        ),

        "similarity": round(
            best_similarity,
            4
        ),

        "confusable_similarity": round(
            best_confusable_similarity,
            4
        ),

        "attack_type": attack_type,
    }


# ============================================================
# Local testing
# ============================================================

if __name__ == "__main__":

    test_urls = [

        # Legitimate
        "https://google.com",

        "https://accounts.google.com",

        "https://microsoft.com",

        # Edit-distance attacks
        "https://gooogle.com",

        "https://gogle.com",

        "https://googl.com",

        "https://googlee.com",

        # Character substitution attacks
        "https://g00gle.com",

        "https://goog1e.com",

        "https://micros0ft.com",

        # Deceptive subdomain
        "https://google.com.evil.com",
    ]

    for url in test_urls:

        result = analyze_typosquatting(url)

        print("\n" + "=" * 60)

        print(
            "URL:",
            url
        )

        print(
            "registered_domain:",
            result["registered_domain"]
        )

        print(
            "possible_typosquatting:",
            result["possible_typosquatting"]
        )

        print(
            "matched_brand:",
            result["matched_brand"]
        )

        print(
            "similarity:",
            result["similarity"]
        )

        print(
            "confusable_similarity:",
            result["confusable_similarity"]
        )

        print(
            "attack_type:",
            result["attack_type"]
        )