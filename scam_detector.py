from config import SCAM_SCORE_THRESHOLD

SCAM_KEYWORDS = [
    "free money", "giveaway", "click the link", "dm me",
    "limited time offer", "guaranteed profit", "crypto investment",
    "double your money", "make money fast", "work from home",
    "passive income", "financial freedom", "earn $", "make $",
    "wire transfer", "send me", "cash app", "venmo", "zelle",
    "paypal me", "act now", "risk free", "100% profit",
    "binary options", "forex signal", "mlm", "pyramid scheme",
    "no risk", "exclusive deal", "secret method", "loophole",
    "i made $", "you can too", "easy money", "instant profit",
    "follow for more tips", "link in bio", "message me",
    "sign up now", "limited spots", "only a few left",
]

SCAM_HASHTAGS = [
    "#crypto", "#nft", "#forex", "#makemoneyonline",
    "#passiveincome", "#financialfreedom", "#workfromhome",
    "#getrichquick", "#investing101", "#sidehustle",
    "#dropshipping", "#affiliatemarketing", "#cryptotrading",
    "#forextrader", "#binaryoptions", "#moneytips",
    "#wealthmindset", "#millionairemindset", "#hustle",
    "#earnmoneyonline",
]

def score_video(video_data: dict) -> int:
    text = (
        video_data.get("description", "") + " " +
        video_data.get("author", "")
    ).lower()
    keyword_score = sum(2 for kw in SCAM_KEYWORDS if kw.lower() in text)
    hashtag_score = sum(1 for ht in SCAM_HASHTAGS if ht.lower() in text)
    return keyword_score + hashtag_score

def is_scam(video_data: dict) -> bool:
    return score_video(video_data) >= SCAM_SCORE_THRESHOLD

def get_scam_reasons(video_data: dict) -> list:
    text = (
        video_data.get("description", "") + " " +
        video_data.get("author", "")
    ).lower()
    reasons = []
    for kw in SCAM_KEYWORDS:
        if kw.lower() in text:
            reasons.append(f"Keyword: '{kw}'")
    for ht in SCAM_HASHTAGS:
        if ht.lower() in text:
            reasons.append(f"Hashtag: '{ht}'")
    return reasons

def get_score_label(score: int) -> str:
    if score == 0:
        return "Clean"
    elif score <= 1:
        return "Low Risk"
    elif score <= 3:
        return "Suspicious"
    elif score <= 6:
        return "Probable Scam"
    else:
        return "Almost Certainly a Scam"