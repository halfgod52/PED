// ── Brand reference list for spoofing / lookalike detection ──────────────
// Extend this map with any additional brands you want to protect against.
const BRAND_DOMAINS = {
  paypal: ["paypal.com"],
  amazon: ["amazon.com"],
  microsoft: ["microsoft.com", "outlook.com", "live.com", "office.com"],
  google: ["google.com", "gmail.com"],
  apple: ["apple.com", "icloud.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com", "fb.com"],
  linkedin: ["linkedin.com"],
  "bank of america": ["bankofamerica.com"],
  chase: ["chase.com"],
  "wells fargo": ["wellsfargo.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  usps: ["usps.com"],
  irs: ["irs.gov"],
  docusign: ["docusign.com"],
  "american express": ["americanexpress.com", "aexp.com"],
};

const WEIGHTS = {
  mismatch: 5,
  lookalikeLink: 4,
  subdomainTrickLink: 4,
  shortener: 2,
  ipLink: 3,
  
  verifyAccount: 3,
  suspiciousLink: 3,
  accountThreat: 3,
  credentialReq: 4,
  urgency: 2,
  prizeScam: 3,
  suspiciousPayment: 4,
  impersonalGreeting: 1,
  insecureHttp: 2,
  ipAddressBody: 3,
  
  displayNameSpoof: 4,
  subdomainTrickSender: 4,
  lookalikeSender: 4,
  replyToSpoof: 5,
  mailedByMismatch: 5,

  dangerousAttachment: 5,
  doubleExtension: 5,
  suspiciousArchive: 3,
};

// ── Full IANA/ICANN top-level domain list ──────────────────────────────────
// Used to validate that a domain-looking substring actually ends in a real
// TLD (generic, country-code, sponsored, infrastructure, or test) before
// trusting it as one — this tightens domain extraction from free-form text
// (link labels, subjects) so things like "readme.txt" or "version.2" don't
// get misread as a domain. Includes internationalized (non-ASCII) TLDs.
const KNOWN_TLDS = new Set([
  "aaa", "aarp", "abarth", "abb", "abbott", "abbvie", "abc", "able",
  "abogado", "abudhabi", "ac", "academy", "accenture", "accountant", "accountants", "aco",
  "active", "actor", "ad", "adac", "ads", "adult", "ae", "aeg",
  "aero", "aetna", "af", "afamilycompany", "afl", "africa", "ag", "agakhan",
  "agency", "ai", "aig", "aigo", "airbus", "airforce", "airtel", "akdn",
  "al", "alfaromeo", "alibaba", "alipay", "allfinanz", "allstate", "ally", "alsace",
  "alstom", "am", "amazon", "americanexpress", "americanfamily", "amex", "amfam", "amica",
  "amsterdam", "an", "analytics", "android", "anquan", "anz", "ao", "aol",
  "apartments", "app", "apple", "aq", "aquarelle", "ar", "arab", "aramco",
  "archi", "army", "arpa", "art", "arte", "as", "asda", "asia",
  "associates", "at", "athleta", "attorney", "au", "auction", "audi", "audible",
  "audio", "auspost", "author", "auto", "autos", "avianca", "aw", "aws",
  "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex",
  "bananarepublic", "band", "bank", "bar", "barcelona", "barclaycard", "barclays", "barefoot",
  "bargains", "baseball", "basketball", "bauhaus", "bayern", "bb", "bbc", "bbt",
  "bbva", "bcg", "bcn", "bd", "be", "beats", "beauty", "beer",
  "bentley", "berlin", "best", "bestbuy", "bet", "bf", "bg", "bh",
  "bharti", "bi", "bible", "bid", "bike", "bing", "bingo", "bio",
  "biz", "bj", "bl", "black", "blackfriday", "blanco", "blockbuster", "blog",
  "bloomberg", "blue", "bm", "bms", "bmw", "bn", "bnl", "bnpparibas",
  "bo", "boats", "boehringer", "bofa", "bom", "bond", "boo", "book",
  "booking", "boots", "bosch", "bostik", "boston", "bot", "boutique", "box",
  "bq", "br", "bradesco", "bridgestone", "broadway", "broker", "brother", "brussels",
  "bs", "bt", "budapest", "bugatti", "build", "builders", "business", "buy",
  "buzz", "bv", "bw", "by", "bz", "bzh", "ca", "cab",
  "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "cancerresearch",
  "canon", "capetown", "capital", "capitalone", "car", "caravan", "cards", "care",
  "career", "careers", "cars", "cartier", "casa", "case", "caseih", "cash",
  "casino", "cat", "catering", "catholic", "cba", "cbn", "cbre", "cbs",
  "cc", "cd", "ceb", "center", "ceo", "cern", "cf", "cfa",
  "cfd", "cg", "ch", "chanel", "channel", "charity", "chase", "chat",
  "cheap", "chintai", "chloe", "christmas", "chrome", "chrysler", "church", "ci",
  "cipriani", "circle", "cisco", "citadel", "citi", "citic", "city", "cityeats",
  "ck", "cl", "claims", "cleaning", "click", "clinic", "clinique", "clothing",
  "cloud", "club", "clubmed", "cm", "cn", "co", "coach", "codes",
  "coffee", "college", "cologne", "com", "comcast", "commbank", "community", "company",
  "compare", "computer", "comsec", "condos", "construction", "consulting", "contact", "contractors",
  "cooking", "cookingchannel", "cool", "coop", "corsica", "country", "coupon", "coupons",
  "courses", "cpa", "cr", "credit", "creditcard", "creditunion", "cricket", "crown",
  "crs", "cruise", "cruises", "csc", "cu", "cuisinella", "cv", "cw",
  "cx", "cy", "cymru", "cyou", "cz", "dabur", "dad", "dance",
  "data", "date", "dating", "datsun", "day", "dclk", "dds", "de",
  "deal", "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta",
  "democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds",
  "diet", "digital", "direct", "directory", "discount", "discover", "dish", "diy",
  "dj", "dk", "dm", "dnp", "do", "docs", "doctor", "dodge",
  "dog", "doha", "domains", "doosan", "dot", "download", "drive", "dtv",
  "dubai", "duck", "dunlop", "duns", "dupont", "durban", "dvag", "dvr",
  "dz", "earth", "eat", "ec", "eco", "edeka", "edu", "education",
  "ee", "eg", "eh", "email", "emerck", "energy", "engineer", "engineering",
  "enterprises", "epost", "epson", "equipment", "er", "ericsson", "erni", "es",
  "esq", "estate", "esurance", "et", "etisalat", "eu", "eurovision", "eus",
  "events", "everbank", "exchange", "expert", "exposed", "express", "extraspace", "fage",
  "fail", "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers",
  "fashion", "fast", "fedex", "feedback", "ferrari", "ferrero", "fi", "fiat",
  "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone",
  "firmdale", "fish", "fishing", "fit", "fitness", "fj", "fk", "flickr",
  "flights", "flir", "florist", "flowers", "flsmidth", "fly", "fm", "fo",
  "foo", "food", "foodnetwork", "football", "ford", "forex", "forsale", "forum",
  "foundation", "fox", "fr", "free", "fresenius", "frl", "frogans", "frontdoor",
  "frontier", "ftr", "fujitsu", "fujixerox", "fun", "fund", "furniture", "futbol",
  "fyi", "ga", "gal", "gallery", "gallo", "gallup", "game", "games",
  "gap", "garden", "gay", "gb", "gbiz", "gd", "gdn", "ge",
  "gea", "gent", "genting", "george", "gf", "gg", "ggee", "gh",
  "gi", "gift", "gifts", "gives", "giving", "gl", "glade", "glass",
  "gle", "global", "globo", "gm", "gmail", "gmbh", "gmo", "gmx",
  "gn", "godaddy", "gold", "goldpoint", "golf", "goo", "goodhands", "goodyear",
  "goog", "google", "gop", "got", "gov", "gp", "gq", "gr",
  "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "gs",
  "gt", "gu", "guardian", "gucci", "guge", "guide", "guitars", "guru",
  "gw", "gy", "hair", "hamburg", "hangout", "haus", "hbo", "hdfc",
  "hdfcbank", "health", "healthcare", "help", "helsinki", "here", "hermes", "hgtv",
  "hiphop", "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm", "hn",
  "hockey", "holdings", "holiday", "homedepot", "homegoods", "homes", "homesense", "honda",
  "honeywell", "horse", "hospital", "host", "hosting", "hot", "hoteles", "hotels",
  "hotmail", "house", "how", "hr", "hsbc", "ht", "htc", "hu",
  "hughes", "hyatt", "hyundai", "ibm", "icbc", "ice", "icu", "id",
  "ie", "ieee", "ifm", "iinet", "ikano", "il", "im", "imamat",
  "imdb", "immo", "immobilien", "in", "inc", "industries", "infiniti", "info",
  "ing", "ink", "institute", "insurance", "insure", "int", "intel", "international",
  "intuit", "investments", "io", "ipiranga", "iq", "ir", "irish", "is",
  "iselect", "ismaili", "ist", "istanbul", "it", "itau", "itv", "iveco",
  "iwc", "jaguar", "java", "jcb", "jcp", "je", "jeep", "jetzt",
  "jewelry", "jio", "jlc", "jll", "jm", "jmp", "jnj", "jo",
  "jobs", "joburg", "jot", "joy", "jp", "jpmorgan", "jprs", "juegos",
  "juniper", "kaufen", "kddi", "ke", "kerryhotels", "kerrylogistics", "kerryproperties", "kfh",
  "kg", "kh", "ki", "kia", "kids", "kim", "kinder", "kindle",
  "kitchen", "kiwi", "km", "kn", "koeln", "komatsu", "kosher", "kp",
  "kpmg", "kpn", "kr", "krd", "kred", "kuokgroup", "kw", "ky",
  "kyoto", "kz", "la", "lacaixa", "ladbrokes", "lamborghini", "lamer", "lancaster",
  "lancia", "lancome", "land", "landrover", "lanxess", "lasalle", "lat", "latino",
  "latrobe", "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc",
  "lefrak", "legal", "lego", "lexus", "lgbt", "li", "liaison", "lidl",
  "life", "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited", "limo",
  "lincoln", "linde", "link", "lipsy", "live", "living", "lixil", "lk",
  "llc", "llp", "loan", "loans", "locker", "locus", "loft", "lol",
  "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "lr", "ls",
  "lt", "ltd", "ltda", "lu", "lundbeck", "lupin", "luxe", "luxury",
  "lv", "ly", "ma", "macys", "madrid", "maif", "maison", "makeup",
  "man", "management", "mango", "map", "market", "marketing", "markets", "marriott",
  "marshalls", "maserati", "mattel", "mba", "mc", "mcd", "mcdonalds", "mckinsey",
  "md", "me", "med", "media", "meet", "melbourne", "meme", "memorial",
  "men", "menu", "meo", "merckmsd", "metlife", "mf", "mg", "mh",
  "miami", "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mk",
  "ml", "mlb", "mls", "mm", "mma", "mn", "mo", "mobi",
  "mobile", "mobily", "moda", "moe", "moi", "mom", "monash", "money",
  "monster", "montblanc", "mopar", "mormon", "mortgage", "moscow", "moto", "motorcycles",
  "mov", "movie", "movistar", "mp", "mq", "mr", "ms", "msd",
  "mt", "mtn", "mtpc", "mtr", "mu", "museum", "music", "mutual",
  "mutuelle", "mv", "mw", "mx", "my", "mz", "na", "nab",
  "nadex", "nagoya", "name", "nationwide", "natura", "navy", "nba", "nc",
  "ne", "nec", "net", "netbank", "netflix", "network", "neustar", "new",
  "newholland", "news", "next", "nextdirect", "nexus", "nf", "nfl", "ng",
  "ngo", "nhk", "ni", "nico", "nike", "nikon", "ninja", "nissan",
  "nissay", "nl", "no", "nokia", "northwesternmutual", "norton", "now", "nowruz",
  "nowtv", "np", "nr", "nra", "nrw", "ntt", "nu", "nyc",
  "nz", "obi", "observer", "off", "office", "okinawa", "olayan", "olayangroup",
  "oldnavy", "ollo", "om", "omega", "one", "ong", "onl", "online",
  "onyourside", "ooo", "open", "oracle", "orange", "org", "organic", "orientexpress",
  "origins", "osaka", "otsuka", "ott", "ovh", "pa", "page", "pamperedchef",
  "panasonic", "panerai", "paris", "pars", "partners", "parts", "party", "passagens",
  "pay", "pccw", "pe", "pet", "pf", "pfizer", "pg", "ph",
  "pharmacy", "phd", "philips", "phone", "photo", "photography", "photos", "physio",
  "piaget", "pics", "pictet", "pictures", "pid", "pin", "ping", "pink",
  "pioneer", "pizza", "pk", "pl", "place", "play", "playstation", "plumbing",
  "plus", "pm", "pn", "pnc", "pohl", "poker", "politie", "porn",
  "post", "pr", "pramerica", "praxi", "press", "prime", "pro", "prod",
  "productions", "prof", "progressive", "promo", "properties", "property", "protection", "pru",
  "prudential", "ps", "pt", "pub", "pw", "pwc", "py", "qa",
  "qpon", "quebec", "quest", "qvc", "racing", "radio", "raid", "re",
  "read", "realestate", "realtor", "realty", "recipes", "red", "redstone", "redumbrella",
  "rehab", "reise", "reisen", "reit", "reliance", "ren", "rent", "rentals",
  "repair", "report", "republican", "rest", "restaurant", "review", "reviews", "rexroth",
  "rich", "richardli", "ricoh", "rightathome", "ril", "rio", "rip", "rmit",
  "ro", "rocher", "rocks", "rodeo", "rogers", "room", "rs", "rsvp",
  "ru", "rugby", "ruhr", "run", "rw", "rwe", "ryukyu", "sa",
  "saarland", "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung",
  "sandvik", "sandvikcoromant", "sanofi", "sap", "sapo", "sarl", "sas", "save",
  "saxo", "sb", "sbi", "sbs", "sc", "sca", "scb", "schaeffler",
  "schmidt", "scholarships", "school", "schule", "schwarz", "science", "scjohnson", "scor",
  "scot", "sd", "se", "search", "seat", "secure", "security", "seek",
  "select", "sener", "services", "ses", "seven", "sew", "sex", "sexy",
  "sfr", "sg", "sh", "shangrila", "sharp", "shaw", "shell", "shia",
  "shiksha", "shoes", "shop", "shopping", "shouji", "show", "showtime", "shriram",
  "si", "silk", "sina", "singles", "site", "sj", "sk", "ski",
  "skin", "sky", "skype", "sl", "sling", "sm", "smart", "smile",
  "sn", "sncf", "so", "soccer", "social", "softbank", "software", "sohu",
  "solar", "solutions", "song", "sony", "soy", "spa", "space", "spiegel",
  "sport", "spot", "spreadbetting", "sr", "srl", "srt", "ss", "st",
  "stada", "staples", "star", "starhub", "statebank", "statefarm", "statoil", "stc",
  "stcgroup", "stockholm", "storage", "store", "stream", "studio", "study", "style",
  "su", "sucks", "supplies", "supply", "support", "surf", "surgery", "suzuki",
  "sv", "swatch", "swiftcover", "swiss", "sx", "sy", "sydney", "symantec",
  "systems", "sz", "tab", "taipei", "talk", "taobao", "target", "tatamotors",
  "tatar", "tattoo", "tax", "taxi", "tc", "tci", "td", "tdk",
  "team", "tech", "technology", "tel", "telecity", "telefonica", "temasek", "tennis",
  "teva", "tf", "tg", "th", "thd", "theater", "theatre", "tiaa",
  "tickets", "tienda", "tiffany", "tips", "tires", "tirol", "tj", "tjmaxx",
  "tjx", "tk", "tkmaxx", "tl", "tm", "tmall", "tn", "to",
  "today", "tokyo", "tools", "top", "toray", "toshiba", "total", "tours",
  "town", "toyota", "toys", "tp", "tr", "trade", "trading", "training",
  "travel", "travelchannel", "travelers", "travelersinsurance", "trust", "trv", "tt", "tube",
  "tui", "tunes", "tushu", "tv", "tvs", "tw", "tz", "ua",
  "ubank", "ubs", "uconnect", "ug", "uk", "um", "unicom", "university",
  "uno", "uol", "ups", "us", "uy", "uz", "va", "vacations",
  "vana", "vanguard", "vc", "ve", "vegas", "ventures", "verisign", "versicherung",
  "vet", "vg", "vi", "viajes", "video", "vig", "viking", "villas",
  "vin", "vip", "virgin", "visa", "vision", "vista", "vistaprint", "viva",
  "vivo", "vlaanderen", "vn", "vodka", "volkswagen", "volvo", "vote", "voting",
  "voto", "voyage", "vu", "vuelos", "wales", "walmart", "walter", "wang",
  "wanggou", "warman", "watch", "watches", "weather", "weatherchannel", "webcam", "weber",
  "website", "wed", "wedding", "weibo", "weir", "wf", "whoswho", "wien",
  "wiki", "williamhill", "win", "windows", "wine", "winners", "wme", "wolterskluwer",
  "woodside", "work", "works", "world", "wow", "ws", "wtc", "wtf",
  "xbox", "xerox", "xfinity", "xihuan", "xin", "测试", "कॉम", "परीक्षा",
  "セール", "佛山", "ಭಾರತ", "慈善", "集团", "在线", "한국", "ଭାରତ",
  "大众汽车", "点看", "คอม", "ভাৰত", "ভারত", "八卦", "ישראל", "موقع",
  "বাংলা", "公益", "公司", "香格里拉", "网站", "移动", "我爱你", "москва",
  "испытание", "қаз", "католик", "онлайн", "сайт", "联通", "срб", "бг",
  "бел", "קום", "时尚", "微博", "테스트", "淡马锡", "ファッション", "орг",
  "नेट", "ストア", "アマゾン", "삼성", "சிங்கப்பூர்", "商标", "商店", "商城",
  "дети", "мкд", "טעסט", "ею", "ポイント", "新闻", "工行", "家電",
  "كوم", "中文网", "中信", "中国", "中國", "娱乐", "谷歌", "భారత్",
  "ලංකා", "電訊盈科", "购物", "測試", "クラウド", "ભારત", "通販", "भारतम्",
  "भारत", "भारोत", "آزمایشی", "பரிட்சை", "网店", "संगठन", "餐厅", "网络",
  "ком", "укр", "香港", "亚马逊", "诺基亚", "食品", "δοκιμή", "飞利浦",
  "إختبار", "台湾", "台灣", "手表", "手机", "мон", "الجزائر", "عمان",
  "ارامكو", "ایران", "العليان", "اتصالات", "امارات", "بازار", "موريتانيا", "پاکستان",
  "الاردن", "موبايلي", "بارت", "بھارت", "المغرب", "ابوظبي", "البحرين", "السعودية",
  "ڀارت", "كاثوليك", "سودان", "همراه", "عراق", "مليسيا", "澳門", "닷컴",
  "政府", "شبكة", "بيتك", "عرب", "გე", "机构", "组织机构", "健康",
  "ไทย", "سورية", "招聘", "рус", "рф", "珠宝", "تونس", "大拿",
  "ລາວ", "みんな", "グーグル", "ευ", "ελ", "世界", "書籍", "ഭാരതം",
  "ਭਾਰਤ", "网址", "닷넷", "コム", "天主教", "游戏", "vermögensberater", "vermögensberatung",
  "企业", "信息", "嘉里大酒店", "嘉里", "مصر", "قطر", "广东", "இலங்கை",
  "இந்தியா", "հայ", "新加坡", "فلسطين", "テスト", "政务", "xperia", "xxx",
  "xyz", "yachts", "yahoo", "yamaxun", "yandex", "ye", "yodobashi", "yoga",
  "yokohama", "you", "youtube", "yt", "yun", "za", "zappos", "zara",
  "zero", "zip", "zippo", "zm", "zone", "zuerich", "zw"
]);

// ── Small utility helpers ─────────────────────────────────────────────────

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function capitalize(s) {
  return s.replace(/\b\w/g, c => c.toUpperCase());
}

// ── Resilient DOM lookup ───────────────────────────────────────────────────
// ── Attachment analysis ───────────────────────────────────────────────────
// Gmail renders attachment chips inside the message footer. The selectors
// below cover the common chip/container variants across Gmail layouts.
const ATTACHMENT_SELECTORS = [".aZo", ".aQH", "[download_url]", ".aV3"];
const ATTACHMENT_ICON_SELECTORS = [".yf img[src*='attachment']", ".brd", ".aZo"];

const DANGEROUS_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "js", "vbs", "vbe", "wsf", "wsh",
  "msi", "jar", "ps1", "reg", "com", "pif", "hta", "cpl", "inf",
  "lnk", "application", "gadget", "msp", "mst", "scf", "ws",
]);

const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "tgz", "bz2"]);

// Extracts visible filenames from Gmail's attachment chips in the open email.
function extractAttachmentNames(emailBody) {
  if (!emailBody) return [];
  const names = [];
  // Primary: ".aV3" spans contain the filename text inside attachment chips
  const parent = emailBody.closest(".h7") || emailBody.parentElement;
  if (!parent) return names;

  for (const sel of ATTACHMENT_SELECTORS) {
    const chips = parent.querySelectorAll(sel);
    for (const chip of chips) {
      // .aV3 is the filename span; .aQA is another variant
      const nameEl = chip.querySelector(".aV3") || chip.querySelector(".aQA") || chip;
      const text = (nameEl.getAttribute("title") || nameEl.innerText || "").trim();
      if (text && text.length > 0 && text.includes(".")) {
        names.push(text);
      }
    }
  }

  // Also check download_url attributes which contain "filename:mimetype:url"
  const downloadEls = parent.querySelectorAll("[download_url]");
  for (const el of downloadEls) {
    const attr = el.getAttribute("download_url") || "";
    const parts = attr.split(":");
    if (parts.length >= 1 && parts[0].includes(".")) {
      names.push(parts[0]);
    }
  }

  // De-duplicate
  return [...new Set(names)];
}

// Extracts the final extension from a filename (lowercased).
function getFinalExtension(filename) {
  const parts = filename.split(".");
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
}

// Checks for double-extension tricks like "invoice.pdf.exe".
function hasDoubleExtension(filename) {
  const parts = filename.split(".");
  if (parts.length < 3) return false;
  const finalExt = parts[parts.length - 1].toLowerCase();
  return DANGEROUS_EXTENSIONS.has(finalExt);
}

// Analyzes attachment filenames for phishing signals.
// bodyText is passed in to detect archive+urgency combos.
function analyzeAttachments(attachmentNames, bodyText) {
  const flags = [];
  let score = 0;
  const seen = new Set();

  for (const name of attachmentNames) {
    const ext = getFinalExtension(name);

    if (hasDoubleExtension(name) && !seen.has("double-ext")) {
      flags.push(`Attachment "${name}" uses a double extension to disguise its real file type`);
      score += WEIGHTS.doubleExtension;
      seen.add("double-ext");
    } else if (DANGEROUS_EXTENSIONS.has(ext) && !seen.has("dangerous-ext")) {
      flags.push(`Attachment "${name}" is a potentially dangerous file type (.${ext})`);
      score += WEIGHTS.dangerousAttachment;
      seen.add("dangerous-ext");
    }

    if (ARCHIVE_EXTENSIONS.has(ext) && !seen.has("suspicious-archive")) {
      // Only flag archives when the email body also contains urgency language
      const urgencyPattern = /\b(urgent|immediately|act now|password|open the attached|see attached|review the attached)\b/i;
      if (urgencyPattern.test(bodyText)) {
        flags.push(`Archive attachment "${name}" combined with urgency language in the email body`);
        score += WEIGHTS.suspiciousArchive;
        seen.add("suspicious-archive");
      }
    }
  }

  return { score, flags };
}

// Gmail renders slightly different markup depending on view mode (full
// conversation view vs. split/reading pane) and hides collapsed messages in
// a multi-message thread rather than removing them. A single hard-coded
// selector breaks in either case. This tries several known selectors in
// priority order and returns the first one that's actually visible on
// screen, rather than the first that merely exists in the DOM.
const EMAIL_BODY_SELECTORS = [".a3s.aiL", ".a3s", ".ii.gt .a3s", "[data-message-id] .a3s"];
const SENDER_SELECTORS = [".gD", ".go .g2", "span.gD", "[email].gD"];

// Gmail shows "mailed-by:" and "signed-by:" in expanded sender details.
// These selectors cover known variants of that UI.
const MAILED_BY_SELECTORS = [
  "td.gH span.g3",         // label inside the sender detail table
  ".gH .g3",               // alternative nesting
  "span[data-hovercard-id]", // hover-card variant
];

// Extracts the "mailed-by" domain from Gmail's expanded sender header.
// Returns null if the element isn't present (e.g. header not expanded).
function extractMailedByDomain() {
  // Try to find the active expanded sender details container.
  // In Gmail, .gE, .ajC, or table.cf.gJ often wraps the expanded header table.
  const activeContainer = findVisible([".gE", ".ajC", "table.cf.gJ", ".go"]);
  if (!activeContainer) return null; // If not expanded, return null immediately.

  // Look for a <td> whose text contains "mailed-by:" or "signed-by:"
  const headerTds = Array.from(activeContainer.querySelectorAll("td"));
  for (const td of headerTds) {
    const text = td.innerText.trim().toLowerCase();
    if (text === "mailed-by:" || text === "signed-by:") {
      const sibling = td.nextElementSibling;
      if (sibling) {
        // Try getting text directly from the sibling
        const domain = sibling.innerText.trim().toLowerCase();
        if (domain && domain.includes(".") && !domain.includes(" ")) return domain;
        
        // Tightened fallback: Check for nested spans (like data-hovercard-id) 
        // ONLY inside this confirmed mailed-by sibling cell.
        const innerEls = sibling.querySelectorAll("span[data-hovercard-id], span.g3");
        for (const el of innerEls) {
          const innerText = el.innerText.trim().toLowerCase();
          if (innerText && innerText.includes(".") && !innerText.includes(" ")) {
            return innerText;
          }
        }
      }
    }
  }

  // Fallback for other known structures, strictly scoped to the active container.
  for (const sel of MAILED_BY_SELECTORS) {
    // Skip raw hovercard selectors here to prevent matching unrelated UI elements
    // if the layout didn't provide a "mailed-by" label.
    if (sel.includes("data-hovercard-id")) continue; 
    
    const els = activeContainer.querySelectorAll(sel);
    for (const el of els) {
      const text = el.innerText.trim().toLowerCase();
      if (text && text.includes(".") && !text.includes(" ")) {
        return text;
      }
    }
  }

  return null;
}

function isVisible(el) {
  return !!el && el.offsetParent !== null;
}

function findVisible(selectors) {
  for (const sel of selectors) {
    const matches = Array.from(document.querySelectorAll(sel));
    // Prefer the last visible match — in an expanded thread, the currently
    // open message is typically the last one rendered, while earlier
    // (collapsed) messages remain in the DOM but hidden.
    const visible = matches.filter(isVisible);
    if (visible.length) return visible[visible.length - 1];
  }
  return null;
}

// Normalizes common homoglyph / lookalike character substitutions so that
// e.g. "micr0soft.com" and "microsoft.com" compare as near-identical.
function normalizeDomain(domain) {
  return domain
    .toLowerCase()
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/8/g, "b");
}

// Standard edit-distance calculation — used to catch typosquatted domains
// (e.g. "paypa1.com" vs "paypal.com" = distance 1).
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

// Best-effort "registrable domain" extraction (last two labels, with a
// small list of common two-part suffixes). Not a full public-suffix-list
// implementation, but good enough for a heuristic scanner.
function getRegistrableDomain(hostname) {
  const twoPartSuffixes = [
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "co.jp", "ne.jp", "or.jp",
    "com.br", "net.br", "org.br", "co.nz", "net.nz", "org.nz",
    "com.mx", "com.cn", "co.il"
  ];
  const parts = hostname.split(".");
  for (const suffix of twoPartSuffixes) {
    if (hostname.endsWith("." + suffix)) {
      const suffixLabelCount = suffix.split(".").length;
      return parts.slice(-(suffixLabelCount + 1)).join(".");
    }
  }
  return parts.slice(-2).join(".");
}

// Catches "paypal.com.verify-secure.net" style tricks: a real brand name
// sitting as its own label somewhere in the hostname, while the actual
// registrable domain is something else entirely.
function checkBrandInSubdomainTrick(hostname, registrableDomain) {
  const labels = hostname.split(".");
  for (const brand in BRAND_DOMAINS) {
    for (const legitDomain of BRAND_DOMAINS[brand]) {
      const brandRoot = legitDomain.split(".")[0];
      if (brandRoot.length >= 3 && labels.includes(brandRoot) && registrableDomain !== legitDomain) {
        return brand;
      }
    }
  }
  return null;
}

// Catches typosquats / homoglyph lookalikes of known brand domains
// (e.g. "micosoft.com", "paypa1.com").
function checkLookalikeDomain(registrableDomain) {
  // 1. Strict match bypass: if it's an exact known domain, it's not a lookalike
  for (const brand in BRAND_DOMAINS) {
    if (BRAND_DOMAINS[brand].includes(registrableDomain)) {
      return null;
    }
  }

  // 2. Expensive homoglyph / edit-distance check
  const normalized = normalizeDomain(registrableDomain);
  for (const brand in BRAND_DOMAINS) {
    for (const legitDomain of BRAND_DOMAINS[brand]) {
      const dist = levenshtein(normalized, normalizeDomain(legitDomain));
      const closeEnoughLength = Math.abs(registrableDomain.length - legitDomain.length) <= 3;
      const maxDist = legitDomain.split(".")[0].length < 6 ? 1 : 2;
      if (dist <= maxDist && closeEnoughLength) {
        return { brand, legitDomain };
      }
    }
  }
  return null;
}

// Catches "PayPal Support <random@sketchy-domain.ru>" — display name
// claims a brand, but the actual sending domain doesn't belong to it.
function checkDisplayNameSpoofing(name, registrableDomain) {
  const lowerName = (name || "").toLowerCase();
  for (const brand in BRAND_DOMAINS) {
    const re = new RegExp("\\b" + escapeRegex(brand) + "\\b", "i");
    if (re.test(lowerName) && !BRAND_DOMAINS[brand].includes(registrableDomain)) {
      return brand;
    }
  }
  return null;
}

// ── Link-target analysis — NEW ─────────────────────────────────────────────
// Known URL shorteners — these hide the real destination, which is itself
// a mild red flag in an email asking you to click something.
const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
];

// Pulls {text, href} off every real link in a container, filtering out
// anchors that aren't actual navigation targets (fragments, mailto, etc.).
function extractLinks(container) {
  if (!container) return [];
  return Array.from(container.querySelectorAll("a[href]"))
    .map(a => ({ text: a.innerText.trim(), href: a.getAttribute("href") || "" }))
    .filter(l => l.href && !/^(#|mailto:|tel:|javascript:)/i.test(l.href));
}

function getHostnameFromUrl(url) {
  try {
    return new URL(url, "https://mail.google.com").hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

// Pulls a domain-looking substring out of a link's visible text, e.g.
// "Verify at paypal.com/login" -> "paypal.com". Used to catch links whose
// displayed text claims one domain while the href goes somewhere else.
// Checks each candidate against KNOWN_TLDS so plain text like "readme.txt"
// or "version.2" isn't misread as a domain just because it has a dot in it.
function extractDomainFromText(text) {
  const candidates = text.matchAll(/([a-z0-9-]+\.)+[a-z]{2,}(?=[\/\s]|$)/gi);
  for (const m of candidates) {
    const candidate = m[0].toLowerCase();
    const tld = candidate.split(".").pop();
    if (KNOWN_TLDS.has(tld)) return candidate;
  }
  return null;
}

// Checks every link in the email body against: text/target mismatch,
// lookalike or brand-in-subdomain tricks on the target itself, shortener
// usage, and raw-IP targets. De-dupes so one phishing email with 10 bad
// links doesn't spam 10 near-identical flags.
function analyzeLinks(links) {
  const flags = [];
  let score = 0;
  const seen = new Set();

  for (const link of links) {
    const hostname = getHostnameFromUrl(link.href);
    if (!hostname) continue;
    const registrableDomain = getRegistrableDomain(hostname);

    const textDomain = extractDomainFromText(link.text);
    if (textDomain && getRegistrableDomain(textDomain) !== registrableDomain && !seen.has("mismatch")) {
      flags.push(`Link text shows "${textDomain}" but actually goes to ${hostname}`);
      score += WEIGHTS.mismatch;
      seen.add("mismatch");
    }

    const lookalike = checkLookalikeDomain(registrableDomain);
    if (lookalike && !seen.has("lookalike-link")) {
      flags.push(`A link goes to ${registrableDomain}, a lookalike of ${lookalike.legitDomain}`);
      score += WEIGHTS.lookalikeLink;
      seen.add("lookalike-link");
    }

    const subdomainTrick = checkBrandInSubdomainTrick(hostname, registrableDomain);
    if (subdomainTrick && !seen.has("subdomain-trick-link")) {
      flags.push(`"${capitalize(subdomainTrick)}" appears in a link's address but isn't the real destination`);
      score += WEIGHTS.subdomainTrickLink;
      seen.add("subdomain-trick-link");
    }

    if (URL_SHORTENERS.includes(registrableDomain) && !seen.has("shortener")) {
      flags.push("A link uses a URL shortener, hiding its real destination");
      score += WEIGHTS.shortener;
      seen.add("shortener");
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) && !seen.has("ip-link")) {
      flags.push("A link's target is a raw IP address instead of a domain");
      score += WEIGHTS.ipLink;
      seen.add("ip-link");
    }
  }

  return { score, flags };
}

// ── Body/subject text analysis (unchanged detection logic) ────────────────
function analyzeText(text) {
  let score = 0;
  const flags = [];

  const redFlags = [
    { pattern: /verify your (account|identity|email|password)/i, label: "Account verification request", weight: WEIGHTS.verifyAccount },
    { pattern: /click (here|below|this link) (to|and) (verify|confirm|update|reset)/i, label: "Suspicious call-to-action link", weight: WEIGHTS.suspiciousLink },
    { pattern: /your account (will be|has been) (suspended|locked|disabled|terminated)/i, label: "Account threat / urgency", weight: WEIGHTS.accountThreat },
    { pattern: /enter your (password|credentials|credit card|ssn|social security)/i, label: "Credential request", weight: WEIGHTS.credentialReq },
    { pattern: /\b(urgent|immediately|act now|respond within \d+ hours?)\b/i, label: "Urgency language", weight: WEIGHTS.urgency },
    { pattern: /\b(won|winner|congratulations).{0,30}(prize|lottery|reward|gift card)/i, label: "Prize / lottery scam", weight: WEIGHTS.prizeScam },
    { pattern: /wire transfer|western union|gift card (payment|code)/i, label: "Suspicious payment method", weight: WEIGHTS.suspiciousPayment },
    { pattern: /dear (customer|user|account holder|valued member)/i, label: "Generic impersonal greeting", weight: WEIGHTS.impersonalGreeting },
    { pattern: /\bhttp:\/\//i, label: "Insecure HTTP link", weight: WEIGHTS.insecureHttp },
    { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, label: "IP address used instead of domain", weight: WEIGHTS.ipAddressBody },
  ];

  for (const flag of redFlags) {
    if (flag.pattern.test(text)) {
      score += flag.weight;
      flags.push(flag.label);
    }
  }

  return { score, flags };
}

// ── Sender (display name + domain) analysis ───────────────────────────────
function analyzeSender(name, email, replyToEmail, mailedByDomain) {
  const flags = [];
  let score = 0;

  if (!email || !email.includes("@")) return { score, flags };

  const hostname = email.split("@")[1].toLowerCase();
  const registrableDomain = getRegistrableDomain(hostname);

  const spoofedBrand = checkDisplayNameSpoofing(name, registrableDomain);
  if (spoofedBrand) {
    flags.push(`Display name says "${capitalize(spoofedBrand)}" but sender domain is ${registrableDomain}`);
    score += WEIGHTS.displayNameSpoof;
  }

  const subdomainTrick = checkBrandInSubdomainTrick(hostname, registrableDomain);
  if (subdomainTrick) {
    flags.push(`"${capitalize(subdomainTrick)}" appears in the sender address but isn't the real domain`);
    score += WEIGHTS.subdomainTrickSender;
  }

  const lookalike = checkLookalikeDomain(registrableDomain);
  if (lookalike) {
    flags.push(`Sender domain (${registrableDomain}) looks like a fake version of ${lookalike.legitDomain}`);
    score += WEIGHTS.lookalikeSender;
  }
  
  if (replyToEmail && replyToEmail.includes("@")) {
    const replyToHostname = replyToEmail.split("@")[1].toLowerCase();
    const replyToRegistrable = getRegistrableDomain(replyToHostname);
    if (replyToRegistrable !== registrableDomain) {
      flags.push(`Reply-To domain (${replyToRegistrable}) does not match sender domain (${registrableDomain})`);
      score += WEIGHTS.replyToSpoof;
    }
  }

  // Mailed-by / signed-by mismatch
  if (mailedByDomain) {
    const mailedByRegistrable = getRegistrableDomain(mailedByDomain);
    if (mailedByRegistrable !== registrableDomain) {
      flags.push(`Mailed-by domain (${mailedByRegistrable}) does not match sender domain (${registrableDomain})`);
      score += WEIGHTS.mailedByMismatch;
    }
  }

  return { score, flags };
}

function scoreToLevel(score) {
  if (score === 0) return "safe";
  if (score <= 3) return "suspicious";
  return "phishing";
}

function levelLabel(level) {
  return level === "safe" ? "✅ Looks Safe" : level === "suspicious" ? "⚠️ Suspicious" : "🚨 Likely Phishing";
}

// Pulls display name + email address from a Gmail sender element. Gmail
// marks sender spans with an `email` attribute (and usually a `name`
// attribute too) both in message headers and inbox list rows.
function senderFromElement(el) {
  if (!el) return { name: "", email: "" };
  return {
    name: el.getAttribute("name") || el.innerText.trim(),
    email: el.getAttribute("email") || "",
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  // --- Scan currently open email ---
  if (request.action === "scan") {
    (async () => {
      try {
        const settings = await new Promise(resolve => chrome.storage.sync.get({ customBrands: [], trustedSenders: [] }, resolve));
        if (settings.customBrands && settings.customBrands.length > 0) {
          BRAND_DOMAINS["Custom Brand"] = settings.customBrands;
        }

        const domFailures = [];
        const emailBody = findVisible(EMAIL_BODY_SELECTORS);
        if (!emailBody) domFailures.push("email body");
        // No whole-page fallback: reading document.body.innerText when the body
        // selector misses would score nav bar / sidebar / other email previews
        // instead of the actual message, producing a misleading result.
        const text = emailBody ? emailBody.innerText : "";

      const senderEl = findVisible(SENDER_SELECTORS);
      if (!senderEl) domFailures.push("sender element");
      const { name, email } = senderFromElement(senderEl);

      const subjectEl = findVisible(["h2.hP", ".hP"]);
      const subject = subjectEl ? subjectEl.innerText.trim() : "(No subject)";

      // Reply-To check
      let replyToEmail = null;
      const replyToLabel = Array.from(document.querySelectorAll("td")).find(td => td.innerText.trim() === "Reply-to:");
      if (replyToLabel && replyToLabel.nextElementSibling) {
        const emailSpan = replyToLabel.nextElementSibling.querySelector("[email]");
        if (emailSpan) {
          replyToEmail = emailSpan.getAttribute("email");
        } else {
          const mailtoLink = replyToLabel.nextElementSibling.querySelector("a[href^='mailto:']");
          if (mailtoLink) replyToEmail = mailtoLink.getAttribute("href").replace("mailto:", "").split("?")[0];
        }
      }

      // Mailed-by / signed-by extraction (only present when header is expanded)
      const mailedByDomain = extractMailedByDomain();

      // If we can't read the body OR the sender, there's nothing real to
      // score — a "Safe" verdict here would just mean "found nothing to
      // flag," which reads as reassurance the scan never actually earned.
      if (!emailBody && !senderEl) {
        sendResponse({
          result: "Couldn't read this email",
          level: "unknown",
          score: null,
          flags: [],
          groups: {},
          domFailures
        });
        return true;
      }

      const links = extractLinks(emailBody);
      const attachmentNames = extractAttachmentNames(emailBody);

      const bodyResult = analyzeText(text);
      const senderResult = analyzeSender(name, email, replyToEmail, mailedByDomain);
      const linkResult = analyzeLinks(links);
      const attachResult = analyzeAttachments(attachmentNames, text);

      const score = bodyResult.score + senderResult.score + linkResult.score + attachResult.score;
      let flags = [...senderResult.flags, ...linkResult.flags, ...bodyResult.flags, ...attachResult.flags];
      let level = scoreToLevel(score);

      const senderHostname = email && email.includes("@") ? email.split("@")[1].toLowerCase() : "";
      if (settings.trustedSenders && (settings.trustedSenders.includes(email.toLowerCase()) || settings.trustedSenders.includes(senderHostname))) {
        level = "safe";
        flags = ["Sender is in your Trusted Senders list"];
      }

      sendResponse({
        result: levelLabel(level),
        level,
        score: level === "safe" && flags.length === 1 ? 0 : score,
        subject,
        senderEmail: email,
        flags,
        groups: {
          sender: senderResult.flags,
          links: linkResult.flags,
          content: bodyResult.flags,
          attachments: attachResult.flags
        },
        domFailures: domFailures.length ? domFailures : undefined
      });
    } catch (err) {
      console.error("PED scan error:", err);
      sendResponse({
        result: "Scan failed",
        level: "unknown",
        score: null,
        flags: [],
        groups: {},
        domFailures: ["unexpected error"]
      });
    }
    })();
    return true;
  }

  // --- Scan inbox rows ---
  if (request.action === "scanInbox") {
    try {
      const domFailures = [];
      const container = document.querySelector("div.AO") || document.querySelector("div[role='main']");
      if (!container) domFailures.push("scrollable container");

      const emails = [];
      const seenThreads = new Set();
      const MAX_ROWS = 200;

      (async () => {
        try {
          const settings = await new Promise(resolve => chrome.storage.sync.get({ customBrands: [], trustedSenders: [] }, resolve));
          if (settings.customBrands && settings.customBrands.length > 0) {
            BRAND_DOMAINS["Custom Brand"] = settings.customBrands;
          }

          let noNewRowsCount = 0;
          let totalScanned = 0;

          while (totalScanned < MAX_ROWS && noNewRowsCount < 2) {
            const rows = Array.from(document.querySelectorAll("tr.zA"));
            let newRowsInThisPass = 0;

            for (const row of rows) {
              if (totalScanned >= MAX_ROWS) break;

              let threadId = row.getAttribute("data-legacy-thread-id");
              if (!threadId) {
                threadId = row.getAttribute("data-ped-thread-id") || ("ped-" + Math.random().toString(36).substring(2, 9));
                row.setAttribute("data-ped-thread-id", threadId);
              }

              if (seenThreads.has(threadId)) continue;
              
              seenThreads.add(threadId);
              newRowsInThisPass++;
              totalScanned++;

              const subjectEl = row.querySelector(".bog, .bqe");
              const snippetEl = row.querySelector(".y2");
              const { name, email } = senderFromElement(row.querySelector("[email]"));

              const subject = subjectEl ? subjectEl.innerText.trim() : "(No subject)";
              const snippet = snippetEl ? snippetEl.innerText.trim() : "";
              const senderName = name || "Unknown";

              const bodyResult = analyzeText(subject + " " + snippet);
              // Pass null for replyToEmail and mailedByDomain since they aren't visible in inbox list
              const senderResult = analyzeSender(senderName, email, null, null);

              const score = bodyResult.score + senderResult.score;
              let flags = [...senderResult.flags, ...bodyResult.flags];
              let level = scoreToLevel(score);

              const senderHostname = email && email.includes("@") ? email.split("@")[1].toLowerCase() : "";
              if (settings.trustedSenders && (settings.trustedSenders.includes(email.toLowerCase()) || settings.trustedSenders.includes(senderHostname))) {
                level = "safe";
                flags = [];
              }

              if (level !== "safe") {
                emails.push({ subject, sender: senderName, level, flags, score, threadId });
              }
            }

            if (newRowsInThisPass === 0) {
              noNewRowsCount++;
            } else {
              noNewRowsCount = 0;
            }

            if (totalScanned < MAX_ROWS && noNewRowsCount < 2 && container) {
              container.scrollBy(0, container.clientHeight || 500);
              await new Promise(r => setTimeout(r, 500)); // wait for Gmail to lazy-render new rows
            }
          }

          if (totalScanned === 0) domFailures.push("inbox rows");

          sendResponse({ emails, totalScanned, domFailures: domFailures.length ? domFailures : undefined });
        } catch (err) {
          console.error("PED inbox scan error (async):", err);
          sendResponse({ emails: [], totalScanned: 0, domFailures: ["unexpected error"] });
        }
      })();
    } catch (err) {
      console.error("PED inbox scan error:", err);
      sendResponse({ emails: [], totalScanned: 0, domFailures: ["unexpected error"] });
    }
    return true; // Keep channel open for async sendResponse
  }

  // --- Open thread by clicking the actual Gmail row ---
  if (request.action === "openThread") {
    try {
      const threadId = request.threadId;
      // Never interpolate an external value straight into a selector string.
      // Even though threadId currently only ever comes from Gmail's own
      // attribute or our own generated ID, this whitelist + CSS.escape keeps
      // it that way if the source of threadId ever changes later — a bad
      // value here would otherwise let it redirect .click() to an unintended
      // element instead of failing safely.
      if (typeof threadId !== "string" || !/^[A-Za-z0-9_-]+$/.test(threadId)) {
        sendResponse({ ok: false });
        return true;
      }
      const safeId = CSS.escape(threadId);
      let row = document.querySelector(`tr[data-legacy-thread-id="${safeId}"]`);
      if (!row) row = document.querySelector(`tr[data-ped-thread-id="${safeId}"]`);

      if (row) {
        row.click();
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false });
      }
    } catch (err) {
      console.error("PED openThread error:", err);
      sendResponse({ ok: false });
    }
    return true;
  }

  return true;
});

if (typeof module !== 'undefined' && module.exports) { module.exports = { checkLookalikeDomain, checkBrandInSubdomainTrick, analyzeSender, BRAND_DOMAINS, extractMailedByDomain, extractDomainFromText, extractLinks, extractAttachmentNames }; }
