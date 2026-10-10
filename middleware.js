import { ipAddress, rewrite, next } from '@vercel/functions';

// ===== BLOCKED IPs — Facebook crawler IPs =====
const BLOCKED_IPS = new Set([
  "13.57.148.235", "54.183.149.156", "44.243.111.67", "173.252.107.115",
  "173.252.107.116", "173.252.107.12", "173.252.69.116", "173.252.69.4",
  "173.252.70.33", "173.252.70.39", "173.252.70.42", "173.252.82.14",
  "173.252.82.15", "173.252.82.22", "173.252.82.53", "173.252.87.28",
  "173.252.87.3", "173.252.95.23", "173.252.95.27", "173.252.95.29",
  "173.252.95.8", "69.171.231.26", "69.171.234.17", "69.63.184.29",
  "69.63.184.35"
]);

// ===== DUNIYA BHAR KE BOTS — user-agent signatures =====
// In mein se koi bhi match ho to seedha verification.html
const BLOCKED_UAS = [
  // --- Generic bot pehchan ---
  "bot", "crawl", "spider", "scraper", "archiver",

  // --- Search engine crawlers ---
  "googlebot", "google-inspectiontool", "googleother", "google-extended",
  "apis-google", "mediapartners-google",
  "bingbot", "bingpreview", "msnbot",
  "slurp", "duckduckbot", "baiduspider", "yandex", "sogou", "exabot", "petalbot",

  // --- AI crawlers ---
  "gptbot", "chatgpt-user", "openai",
  "claudebot", "claude-user", "anthropic",
  "perplexitybot", "perplexity",
  "bytespider", "bytedance",
  "ccbot", "commoncrawl",
  "youbot", "andibot", "cohere-ai", "diffbot",
  "meta-externalagent", "meta-webindexer", "facebookbot",
  "applebot", "imgsift", "magpie-crawler",
  "omgili", "omgilibot",

  // --- Social media scrapers / link preview bots ---
  "facebookplatform",
  "twitterbot", "linkedinbot", "slackbot", "discordbot",
  "telegrambot", "whatsapp", "pinterest", "redditbot",
  "vkshare", "skypeuripreview",

  // --- SEO / audit tools ---
  "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "rogerbot",
  "screaming frog", "sitebulb", "seokicks", "dataforseo",

  // --- Uptime monitors ---
  "uptimerobot", "pingdom", "statuscake",

  // --- Headless browsers / automation ---
  "headless", "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",

  // --- Scripting / CLI tools ---
  "curl", "wget", "python-requests", "python-urllib",
  "libwww-perl", "httpclient",
  "scrapy", "mechanize", "nutch", "heritrix", "httrack",
];

// ===== Bot / datacenter networks (ASN) =====
const BOT_ASNS = new Set([
  "32934", "11917", "34825", "54115", "63293",  // Facebook (Meta)
  "15169", "396982",                            // Google
  "16509", "14618",                             // Amazon AWS
  "8075",                                       // Microsoft Azure
  "14061",                                      // DigitalOcean
  "16276",                                      // OVH
  "24940",                                      // Hetzner
  "20473",                                      // Vultr / Constant
  "51167",                                      // Contabo
]);

// ===== Blocked countries (datacenter hubs) =====
const BLOCKED_COUNTRIES = new Set(["SE", "IE"]);

// ===== Facebook referrer hosts — verification par =====
// l.facebook.com aur lm.facebook.com is mein NAHI — wahan se aane wale asal users hain
const FB_REFERRER_HOSTS = new Set([
  "m.facebook.com", "facebook.com", "fb.com",
  "www.facebook.com", "web.facebook.com",
]);

export default function middleware(request) {
  const url = new URL(request.url);

  // robots.txt mangne wala seedha verification par
  // (ye check sab se pehle — kyunke '/robots.txt' mein '.' hai)
  if (url.pathname === '/robots.txt') {
    return rewrite(new URL('/verification.html', request.url));
  }

  // verification page aur static files ko check nahi karna — seedha next()
  if (
    url.pathname === '/verification.html' ||
    url.pathname.startsWith('/_next/') ||
    url.pathname.includes('.')
  ) {
    return next();
  }

  const clientIP = ipAddress(request) || "";
  const userAgent = request.headers.get('user-agent') || "";
  const referer = (request.headers.get('referer') || "").toLowerCase();

  // ===== FACEBOOK LINK CRAWLER EXCEPTION =====
  // Ye crawler sirf link ka preview card banata hai — isay verification par
  // NAHI bhejna taake Facebook par preview theek bane. Crawler button nahi
  // dabata, is liye isay asal page dikhane mein koi risk nahi; crawler aur
  // user dono ko wahi ek page milta hai, to ye cloaking bhi nahi.
  // (Ye check sab se pehle hai — crawler Facebook ke IPs/ASNs se bhi aata hai.)
  const FB_CRAWLER_UAS = ["facebookexternalhit", "facebot", "facebookcatalog"];
  if (FB_CRAWLER_UAS.some((s) => userAgent.toLowerCase().includes(s))) {
    return next();
  }

  // Vercel Edge se original ASN aur Country
  const clientASN = request.headers.get('x-vercel-ip-as-number') || "";
  const clientCountry = request.headers.get('x-vercel-ip-country') || "";


  let triggerVerification = false;

  // 0. FACEBOOK REFERRER CHECK
  if (!triggerVerification && referer) {
    try {
      const refHost = new URL(referer).hostname.toLowerCase();
      if (FB_REFERRER_HOSTS.has(refHost)) {
        triggerVerification = true;
      }
    } catch (e) { /* invalid referer — ignore */ }
  }

  // 1. COUNTRY CHECK
  if (!triggerVerification && clientCountry && BLOCKED_COUNTRIES.has(clientCountry.toUpperCase())) {
    triggerVerification = true;
  }

  // 2. ASN CHECK
  if (!triggerVerification && clientASN && BOT_ASNS.has(clientASN)) {
    triggerVerification = true;
  }

  // 3. IP CHECK
  if (!triggerVerification && BLOCKED_IPS.has(clientIP)) {
    triggerVerification = true;
  }

  // 4. USER-AGENT CHECK
  if (!triggerVerification) {
    const uaLower = userAgent.toLowerCase();
    for (const ua of BLOCKED_UAS) {
      if (uaLower.includes(ua)) {
        triggerVerification = true;
        break;
      }
    }
  }

  // Match ho jaye to bina URL badle verification page
  if (triggerVerification) {
    return rewrite(new URL('/verification.html', request.url));
  }

  return next();
}

export const config = {
  // '/:path*' — HAR page cover, koi rasta khula nahi chhute ga
  matcher: ['/:path*'],
};
