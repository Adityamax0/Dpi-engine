"""
========================================================
  app_classifier.py — SNI → Application Classifier
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
========================================================

Aditya's design note:
    This is essentially a domain-matching lookup system.
    In a production environment, this could be backed by
    a trained ML model or a regularly-updated threat feed.
    For this system, I've implemented a tiered matching:
      1. Exact match (fastest)
      2. Suffix match (covers subdomains)
      3. Keyword match (fallback)

    This tiered strategy is a good example of optimizing
    for the common case: most traffic goes to well-known
    domains that will hit tier 1 or 2 immediately.
"""

import logging
from typing import Optional, Dict, List, Tuple
from enum import Enum

logger = logging.getLogger("AppClassifier")


class AppCategory(Enum):
    """
    High-level categories for detected applications.
    Used for category-level blocking (e.g., block all SOCIAL_MEDIA).
    """
    STREAMING    = "Streaming"
    SOCIAL_MEDIA = "Social Media"
    MESSAGING    = "Messaging"
    PRODUCTIVITY = "Productivity"
    SECURITY     = "Security"
    GAMING       = "Gaming"
    DEVELOPER    = "Developer Tools"
    CDN          = "CDN / Infrastructure"
    UNKNOWN      = "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Domain → App Name + Category Mapping
# Built and curated by Aditya Pandey
# Format: (domain_suffix, app_name, category)
# ─────────────────────────────────────────────────────────────────────────────
APP_SIGNATURES: List[Tuple[str, str, AppCategory]] = [
    # ── Streaming ──
    ("youtube.com",         "YouTube",       AppCategory.STREAMING),
    ("googlevideo.com",     "YouTube",       AppCategory.STREAMING),
    ("ytimg.com",           "YouTube",       AppCategory.STREAMING),
    ("netflix.com",         "Netflix",       AppCategory.STREAMING),
    ("nflxvideo.net",       "Netflix",       AppCategory.STREAMING),
    ("primevideo.com",      "Amazon Prime",  AppCategory.STREAMING),
    ("hotstar.com",         "Hotstar",       AppCategory.STREAMING),
    ("spotify.com",         "Spotify",       AppCategory.STREAMING),
    ("scdn.co",             "Spotify",       AppCategory.STREAMING),
    ("twitch.tv",           "Twitch",        AppCategory.STREAMING),
    ("tiktok.com",          "TikTok",        AppCategory.STREAMING),
    ("tiktokv.com",         "TikTok",        AppCategory.STREAMING),

    # ── Social Media ──
    ("facebook.com",        "Facebook",      AppCategory.SOCIAL_MEDIA),
    ("fbcdn.net",           "Facebook",      AppCategory.SOCIAL_MEDIA),
    ("instagram.com",       "Instagram",     AppCategory.SOCIAL_MEDIA),
    ("cdninstagram.com",    "Instagram",     AppCategory.SOCIAL_MEDIA),
    ("twitter.com",         "Twitter/X",     AppCategory.SOCIAL_MEDIA),
    ("twimg.com",           "Twitter/X",     AppCategory.SOCIAL_MEDIA),
    ("x.com",               "Twitter/X",     AppCategory.SOCIAL_MEDIA),
    ("linkedin.com",        "LinkedIn",      AppCategory.SOCIAL_MEDIA),
    ("snapchat.com",        "Snapchat",      AppCategory.SOCIAL_MEDIA),
    ("reddit.com",          "Reddit",        AppCategory.SOCIAL_MEDIA),
    ("redd.it",             "Reddit",        AppCategory.SOCIAL_MEDIA),

    # ── Messaging ──
    ("whatsapp.com",        "WhatsApp",      AppCategory.MESSAGING),
    ("whatsapp.net",        "WhatsApp",      AppCategory.MESSAGING),
    ("telegram.org",        "Telegram",      AppCategory.MESSAGING),
    ("t.me",                "Telegram",      AppCategory.MESSAGING),
    ("discord.com",         "Discord",       AppCategory.MESSAGING),
    ("discordapp.com",      "Discord",       AppCategory.MESSAGING),
    ("signal.org",          "Signal",        AppCategory.MESSAGING),

    # ── Productivity / Business ──
    ("zoom.us",             "Zoom",          AppCategory.PRODUCTIVITY),
    ("google.com",          "Google",        AppCategory.PRODUCTIVITY),
    ("googleapis.com",      "Google APIs",   AppCategory.PRODUCTIVITY),
    ("gstatic.com",         "Google Static", AppCategory.PRODUCTIVITY),
    ("gmail.com",           "Gmail",         AppCategory.PRODUCTIVITY),
    ("microsoft.com",       "Microsoft",     AppCategory.PRODUCTIVITY),
    ("office.com",          "Microsoft Office", AppCategory.PRODUCTIVITY),
    ("teams.microsoft.com", "MS Teams",      AppCategory.PRODUCTIVITY),
    ("slack.com",           "Slack",         AppCategory.PRODUCTIVITY),
    ("notion.so",           "Notion",        AppCategory.PRODUCTIVITY),

    # ── Developer Tools ──
    ("github.com",          "GitHub",        AppCategory.DEVELOPER),
    ("githubusercontent.com","GitHub",        AppCategory.DEVELOPER),
    ("stackoverflow.com",   "StackOverflow", AppCategory.DEVELOPER),
    ("pypi.org",            "PyPI",          AppCategory.DEVELOPER),
    ("npmjs.com",           "NPM",           AppCategory.DEVELOPER),
    ("docker.com",          "Docker Hub",    AppCategory.DEVELOPER),
    ("anthropic.com",       "Anthropic/Claude", AppCategory.DEVELOPER),

    # ── Security / VPN ──
    ("nordvpn.com",         "NordVPN",       AppCategory.SECURITY),
    ("expressvpn.com",      "ExpressVPN",    AppCategory.SECURITY),

    # ── CDN / Infrastructure ──
    ("cloudflare.com",      "Cloudflare",    AppCategory.CDN),
    ("akamai.com",          "Akamai",        AppCategory.CDN),
    ("fastly.com",          "Fastly",        AppCategory.CDN),
    ("amazonaws.com",       "AWS",           AppCategory.CDN),
    ("cloudfront.net",      "AWS CloudFront",AppCategory.CDN),
]


class AppClassifier:
    """
    Classifies a domain/SNI into a known application name and category.

    Matching Strategy (Aditya Pandey):
        Tier 1 — Exact match:   "github.com" → GitHub
        Tier 2 — Suffix match:  "api.github.com" → GitHub (matches ".github.com")
        Tier 3 — Unknown:       return None

    The suffix-based matching handles subdomains automatically,
    which is essential since CDNs and large services use dozens
    of subdomains (e.g. s3.amazonaws.com, eu-west-1.amazonaws.com).
    """

    def __init__(self):
        # Build lookup dict for O(1) exact matching
        self._exact: Dict[str, Tuple[str, AppCategory]] = {}
        self._suffixes: List[Tuple[str, str, AppCategory]] = []

        for domain, app, category in APP_SIGNATURES:
            self._exact[domain] = (app, category)
            self._suffixes.append((domain, app, category))

        logger.debug(f"AppClassifier loaded {len(self._exact)} app signatures")

    def classify(self, sni: str) -> Optional[str]:
        """
        Classify an SNI hostname into an app name.
        Returns app name string, or None if unknown.
        """
        if not sni:
            return None

        domain = sni.lower().strip()

        # Tier 1: exact match
        if domain in self._exact:
            app, cat = self._exact[domain]
            logger.debug(f"Exact match: {domain} → {app} [{cat.value}]")
            return app

        # Tier 2: suffix match (subdomain handling)
        for sig_domain, app, cat in self._suffixes:
            if domain.endswith("." + sig_domain) or domain == sig_domain:
                logger.debug(f"Suffix match: {domain} → {app} [{cat.value}]")
                return app

        return None

    def classify_with_category(self, sni: str) -> Tuple[Optional[str], AppCategory]:
        """Returns (app_name, category) tuple."""
        if not sni:
            return None, AppCategory.UNKNOWN

        domain = sni.lower().strip()

        if domain in self._exact:
            return self._exact[domain]

        for sig_domain, app, cat in self._suffixes:
            if domain.endswith("." + sig_domain) or domain == sig_domain:
                return app, cat

        return None, AppCategory.UNKNOWN

    def get_all_apps(self) -> List[str]:
        """Return list of all known app names."""
        return list(set(app for _, (app, _) in self._exact.items()))
