package com.example.netsecure.data

import com.example.netsecure.data.model.TrafficCategory

/**
 * Classifies network connections into [TrafficCategory] based on domain/SNI,
 * L7 protocol, and destination heuristics.
 *
 * Uses efficient suffix-matching on domains (no regex).
 * This is a core differentiator from PCAPdroid — raw connections become
 * meaningful categories like "Social Media" or "Ads & Trackers".
 */
object TrafficClassifier {

    /**
     * Domain suffix → category mapping.
     * Order: more specific suffixes first in each category.
     */
    private val domainRules: List<Pair<String, TrafficCategory>> by lazy { buildDomainRules() }

    /**
     * Classify a connection by its domain/SNI, L7 protocol, and destination IP.
     *
     * @param domain  The SNI, info, or URL from ConnectionDescriptor
     * @param l7proto The L7 protocol string from nDPI (e.g., "TLS.Facebook")
     * @param dstIp   The destination IP address
     * @param dstPort The destination port
     * @return The matched [TrafficCategory]
     */
    fun classify(
        domain: String,
        l7proto: String,
        dstIp: String,
        dstPort: Int
    ): TrafficCategory {
        // 1. Try L7 protocol hints from nDPI (often contains service name)
        classifyByL7Proto(l7proto)?.let { return it }

        // 2. Try domain/SNI suffix matching
        val normalizedDomain = normalizeDomain(domain)
        if (normalizedDomain.isNotEmpty()) {
            classifyByDomain(normalizedDomain)?.let { return it }
        }

        // 3. IP-based heuristics
        classifyByIp(dstIp, dstPort)?.let { return it }

        // 4. Fallback
        return TrafficCategory.OTHER
    }

    /**
     * Classify based on nDPI's L7 protocol string.
     * nDPI labels look like: "TLS.Facebook", "HTTP.Google", "QUIC.YouTube", etc.
     */
    private fun classifyByL7Proto(l7proto: String): TrafficCategory? {
        if (l7proto.isEmpty()) return null
        val upper = l7proto.uppercase()

        // nDPI names for services
        return l7ProtoMap.entries.firstOrNull { (key, _) ->
            upper.contains(key)
        }?.value
    }

    /**
     * Classify based on domain suffix matching.
     * Checks if the domain ends with any known suffix.
     */
    private fun classifyByDomain(domain: String): TrafficCategory? {
        for ((suffix, category) in domainRules) {
            if (domain == suffix || domain.endsWith(".$suffix")) {
                return category
            }
        }
        return null
    }

    /**
     * Classify based on destination IP heuristics.
     */
    private fun classifyByIp(dstIp: String, dstPort: Int): TrafficCategory? {
        // Private / local IPs → SYSTEM
        if (isPrivateIp(dstIp)) return TrafficCategory.SYSTEM

        // Common system ports
        if (dstPort == 53 || dstPort == 5353) return TrafficCategory.SYSTEM // DNS
        if (dstPort == 123) return TrafficCategory.SYSTEM // NTP

        return null
    }

    private fun normalizeDomain(domain: String): String {
        // Strip protocol prefix, path, port — keep just the hostname
        var d = domain.lowercase().trim()
        // Remove scheme
        val schemeIdx = d.indexOf("://")
        if (schemeIdx >= 0) d = d.substring(schemeIdx + 3)
        // Remove path
        val slashIdx = d.indexOf('/')
        if (slashIdx >= 0) d = d.substring(0, slashIdx)
        // Remove port
        val colonIdx = d.lastIndexOf(':')
        if (colonIdx >= 0) {
            val afterColon = d.substring(colonIdx + 1)
            if (afterColon.all { it.isDigit() }) {
                d = d.substring(0, colonIdx)
            }
        }
        return d
    }

    private fun isPrivateIp(ip: String): Boolean {
        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("172.") && run {
                    val second = ip.substringAfter("172.").substringBefore(".").toIntOrNull() ?: 0
                    second in 16..31
                } ||
                ip.startsWith("127.") ||
                ip == "::1" ||
                ip.startsWith("fe80:")
    }

    // ──────────────────────────────────────────────
    //  L7 Protocol name → Category
    // ──────────────────────────────────────────────

    private val l7ProtoMap = linkedMapOf(
        // Social Media
        "FACEBOOK" to TrafficCategory.SOCIAL_MEDIA,
        "INSTAGRAM" to TrafficCategory.SOCIAL_MEDIA,
        "TWITTER" to TrafficCategory.SOCIAL_MEDIA,
        "TIKTOK" to TrafficCategory.SOCIAL_MEDIA,
        "SNAPCHAT" to TrafficCategory.SOCIAL_MEDIA,
        "LINKEDIN" to TrafficCategory.SOCIAL_MEDIA,
        "REDDIT" to TrafficCategory.SOCIAL_MEDIA,
        "PINTEREST" to TrafficCategory.SOCIAL_MEDIA,
        "TUMBLR" to TrafficCategory.SOCIAL_MEDIA,

        // Streaming
        "YOUTUBE" to TrafficCategory.STREAMING,
        "NETFLIX" to TrafficCategory.STREAMING,
        "SPOTIFY" to TrafficCategory.STREAMING,
        "TWITCH" to TrafficCategory.STREAMING,
        "DISNEY" to TrafficCategory.STREAMING,
        "HULU" to TrafficCategory.STREAMING,
        "DAZN" to TrafficCategory.STREAMING,
        "VIMEO" to TrafficCategory.STREAMING,
        "SOUNDCLOUD" to TrafficCategory.STREAMING,
        "PRIMEVIDEO" to TrafficCategory.STREAMING,
        "HOTSTAR" to TrafficCategory.STREAMING,
        "JIOCINEMA" to TrafficCategory.STREAMING,

        // Messaging
        "WHATSAPP" to TrafficCategory.MESSAGING,
        "TELEGRAM" to TrafficCategory.MESSAGING,
        "SIGNAL" to TrafficCategory.MESSAGING,
        "DISCORD" to TrafficCategory.MESSAGING,
        "SLACK" to TrafficCategory.MESSAGING,
        "SKYPE" to TrafficCategory.MESSAGING,
        "ZOOM" to TrafficCategory.MESSAGING,
        "TEAMS" to TrafficCategory.MESSAGING,
        "VIBER" to TrafficCategory.MESSAGING,
        "LINE" to TrafficCategory.MESSAGING,
        "WECHAT" to TrafficCategory.MESSAGING,

        // Gaming
        "STEAM" to TrafficCategory.GAMING,
        "XBOX" to TrafficCategory.GAMING,
        "PLAYSTATION" to TrafficCategory.GAMING,
        "EPICGAMES" to TrafficCategory.GAMING,
        "RIOT" to TrafficCategory.GAMING,

        // Shopping
        "AMAZON" to TrafficCategory.SHOPPING,
        "EBAY" to TrafficCategory.SHOPPING,

        // Cloud
        "GOOGLE" to TrafficCategory.CLOUD_SERVICES,
        "MICROSOFT" to TrafficCategory.CLOUD_SERVICES,
        "APPLE" to TrafficCategory.CLOUD_SERVICES,
        "DROPBOX" to TrafficCategory.CLOUD_SERVICES,
        "ONEDRIVE" to TrafficCategory.CLOUD_SERVICES,

        // System
        "DNS" to TrafficCategory.SYSTEM,
        "NTP" to TrafficCategory.SYSTEM,
        "MDNS" to TrafficCategory.SYSTEM,
        "SSDP" to TrafficCategory.SYSTEM,
        "DHCP" to TrafficCategory.SYSTEM,
        "LLMNR" to TrafficCategory.SYSTEM,
        "NETBIOS" to TrafficCategory.SYSTEM,

        // CDN
        "AKAMAI" to TrafficCategory.CDN,
        "CLOUDFLARE" to TrafficCategory.CDN,
    )

    // ──────────────────────────────────────────────
    //  Domain suffix rules (built once, cached)
    // ──────────────────────────────────────────────

    private fun buildDomainRules(): List<Pair<String, TrafficCategory>> {
        val rules = mutableListOf<Pair<String, TrafficCategory>>()

        fun addAll(category: TrafficCategory, vararg domains: String) {
            for (d in domains) rules.add(d to category)
        }

        // ── Ads & Trackers (check FIRST — most important for privacy) ──
        addAll(
            TrafficCategory.ADS_TRACKERS,
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "google-analytics.com", "analytics.google.com", "googletagmanager.com",
            "googletagservices.com", "adservice.google.com",
            "graph.facebook.com", "pixel.facebook.com",
            "ads.facebook.com", "an.facebook.com",
            "appsflyer.com", "app.appsflyer.com",
            "adjust.com", "app.adjust.com",
            "branch.io", "app.link", "bnc.lt",
            "crashlytics.com", "firebase-settings.crashlytics.com",
            "app-measurement.com", "firebase.googleapis.com",
            "mixpanel.com", "api.mixpanel.com",
            "amplitude.com", "api.amplitude.com",
            "segment.io", "api.segment.io", "cdn.segment.com",
            "mopub.com", "ads.mopub.com",
            "unity3d.com", "unityads.unity3d.com",
            "admob.com", "pagead2.googlesyndication.com",
            "inmobi.com", "sdk.inmobi.com",
            "chartboost.com",
            "flurry.com", "data.flurry.com",
            "kochava.com",
            "moat.com", "z.moatads.com",
            "scorecardresearch.com",
            "criteo.com", "bidder.criteo.com",
            "taboola.com",
            "outbrain.com",
            "adcolony.com",
            "vungle.com",
            "ironsrc.com", "is.com",
            "liftoff.io",
            "mintegral.com",
            "smaato.com",
            "pubmatic.com",
            "openx.net",
            "rubiconproject.com",
            "adsrvr.org",
            "demdex.net",
            "omtrdc.net",
            "2mdn.net",
            "serving-sys.com",
            "quantserve.com",
            "rlcdn.com",
            "bluekai.com",
            "exelator.com",
            "adnxs.com",
            "contextweb.com"
        )

        // ── Social Media ──
        addAll(
            TrafficCategory.SOCIAL_MEDIA,
            "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com",
            "instagram.com", "cdninstagram.com",
            "twitter.com", "x.com", "twimg.com", "t.co",
            "tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com",
            "snapchat.com", "snap.com", "sc-cdn.net", "snapkit.co",
            "linkedin.com", "licdn.com",
            "reddit.com", "redditmedia.com", "redd.it", "redditstatic.com",
            "pinterest.com", "pinimg.com",
            "tumblr.com",
            "quora.com",
            "threads.net"
        )

        // ── Streaming ──
        addAll(
            TrafficCategory.STREAMING,
            "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "yt3.ggpht.com",
            "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net",
            "spotify.com", "scdn.co", "spotifycdn.com",
            "twitch.tv", "jtvnw.net", "ttvnw.net",
            "disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com",
            "hulu.com", "hulustream.com",
            "primevideo.com", "aiv-cdn.net",
            "hotstar.com", "hotstar-cdn.com",
            "jiocinema.com",
            "voot.com",
            "zee5.com",
            "sonyliv.com",
            "vimeo.com", "vimeocdn.com",
            "soundcloud.com", "sndcdn.com",
            "deezer.com",
            "pandora.com",
            "dailymotion.com", "dm-event.net",
            "crunchyroll.com"
        )

        // ── Messaging ──
        addAll(
            TrafficCategory.MESSAGING,
            "whatsapp.net", "whatsapp.com",
            "telegram.org", "t.me", "telegram.me",
            "signal.org", "signal.art",
            "discord.com", "discordapp.com", "discord.gg", "discord.media",
            "slack.com", "slack-edge.com", "slack-msgs.com",
            "skype.com", "skype.net",
            "zoom.us", "zoom.com", "zoomgov.com",
            "teams.microsoft.com", "teams.live.com",
            "viber.com",
            "line.me", "line-scdn.net",
            "wechat.com", "weixin.qq.com",
            "kakaocorp.com", "kakao.com",
            "duo.google.com", "meet.google.com",
            "webex.com"
        )

        // ── Gaming ──
        addAll(
            TrafficCategory.GAMING,
            "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
            "xbox.com", "xboxlive.com",
            "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
            "epicgames.com", "unrealengine.com",
            "riotgames.com", "leagueoflegends.com",
            "ea.com", "origin.com",
            "battle.net", "blizzard.com",
            "supercell.com",
            "garena.com",
            "mihoyo.com", "hoyoverse.com",
            "roblox.com", "rbxcdn.com",
            "mojang.com", "minecraft.net"
        )

        // ── Shopping ──
        addAll(
            TrafficCategory.SHOPPING,
            "amazon.com", "amazon.in", "amazon.co.uk", "amazonpay.in",
            "flipkart.com", "flixcart.com",
            "myntra.com",
            "ebay.com",
            "etsy.com",
            "walmart.com",
            "shopify.com",
            "aliexpress.com",
            "meesho.com",
            "ajio.com",
            "nykaa.com",
            "swiggy.com",
            "zomato.com",
            "uber.com", "ubereats.com",
            "ola.money", "olacabs.com",
            "paytm.com", "paytmmall.com",
            "phonepe.com",
            "razorpay.com",
            "gpay.app"
        )

        // ── Cloud Services ──
        addAll(
            TrafficCategory.CLOUD_SERVICES,
            "googleapis.com", "google.com", "gstatic.com", "gvt1.com", "gvt2.com",
            "1e100.net",
            "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
            "office.com", "office365.com", "sharepoint.com",
            "azure.com", "azure.net", "azureedge.net", "msedge.net",
            "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
            "amazonaws.com", "aws.amazon.com", "awsstatic.com",
            "dropbox.com", "dropboxapi.com",
            "onedrive.com", "onedrive.live.com",
            "drive.google.com",
            "github.com", "github.io", "githubusercontent.com",
            "gitlab.com"
        )

        // ── System / OS ──
        addAll(
            TrafficCategory.SYSTEM,
            "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
            "android.googleapis.com", "android.clients.google.com",
            "mtalk.google.com",
            "play.googleapis.com", "play.google.com",
            "time.google.com", "time.android.com",
            "android.com",
            "clients1.google.com", "clients2.google.com",
            "clients3.google.com", "clients4.google.com",
            "update.googleapis.com",
            "captive.apple.com",
            "windowsupdate.com", "update.microsoft.com",
            "settings-win.data.microsoft.com"
        )

        // ── CDN / Infrastructure ──
        addAll(
            TrafficCategory.CDN,
            "akamai.net", "akamaized.net", "akamaihd.net", "akadns.net",
            "cloudflare.com", "cloudflare-dns.com", "cloudflare.net", "cf-dns.com",
            "cloudfront.net",
            "fastly.net", "fastlylb.net",
            "edgecastcdn.net", "edgecast.com",
            "stackpathdns.com", "stackpathcdn.com",
            "cdn77.org",
            "limelight.com", "llnw.net",
            "cachefly.net",
            "incapdns.net", "impervadns.net",
            "edgesuite.net",
            "footprint.net",
            "nsone.net",
            "dnspod.com",
            "dnsv1.com"
        )

        return rules
    }
}
