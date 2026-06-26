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

def parse_count(value: str) -> int: 
    # converts values like 12.3M or 13K to integer values

    value = value.strip().upper().replace(",","")

    if not value: 
        return 0
    try: 
        if value.endswith("M"):
            return int(float(value[:-1])*1_000_000)
        if value.endswith("K"):
            return int(float(value[:-1]) * 1_000)
        return int(float(value))
    except ValueError:
        return 0

def score_video(video_data: dict) -> int:
    sum_score = 0 
    text = (
        video_data.get("description", "") + " " +
        video_data.get("author", "")
    ).lower()
    keyword_score = sum(2 for kw in SCAM_KEYWORDS if kw.lower() in text)
    hashtag_score = sum(1 for ht in SCAM_HASHTAGS if ht.lower() in text)

    likes = parse_count(video_data.get("likes", ""))
    comments = parse_count(video_data.get("comments", ""))
    shares = parse_count(video_data.get("shares", ""))

    if likes < 5000 : 
        sum_score += 1
    if comments < 25 : 
        sum_score += 1
    if shares < 10 : 
        sum_score += 1

    return sum_score + keyword_score + hashtag_score

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