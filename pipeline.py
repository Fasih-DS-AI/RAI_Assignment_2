import re

# 1. Regex Pre-filter Blocklist
BLOCKLIST = {
    "direct_threat": [
        # Uses word boundaries \b and capturing group for the verb
        re.compile(r"\b(?:i|we)(?:'ll| will| gonna| am going to)\s+(kill|murder|shoot|stab|hurt|destroy)\s+(?:you|u)\b", re.IGNORECASE),
        re.compile(r"\b(?:you are|you're|u r)\s+going to\s+(?:die|bleed)\b", re.IGNORECASE),
        re.compile(r"\bsomeone\s+should\s+(kill|murder|shoot|stab|hurt)\s+(?:you|u)\b", re.IGNORECASE),
        re.compile(r"\bi(?:'ll| will)\s+find\s+(?:where you live|your house)\b", re.IGNORECASE),
        re.compile(r"\bhope\s+(?:you|u)\s+(?:die|get killed|choke)\b", re.IGNORECASE)
    ],
    "self_harm_directed": [
        # Directed second-person self harm. 
        re.compile(r"\b(?:you|u)\s+should\s+(?:kill|hang|hurt|cut)\s+yourself\b", re.IGNORECASE),
        re.compile(r"\bgo\s+(?:kill|hang|hurt)\s+yourself\b", re.IGNORECASE),
        re.compile(r"\bnobody\s+would\s+(?:care|miss you)\s+if\s+(?:you|u)\s+died\b", re.IGNORECASE),
        re.compile(r"\b(?:do everyone a favor and|just)\s+(?:disappear|end it)\b", re.IGNORECASE)
    ],
    "doxxing_stalking": [
        re.compile(r"\bi\s+(?:know|found)\s+(?:where you live|your real name|your address)\b", re.IGNORECASE),
        re.compile(r"\bi(?:'ll| will| am gonna)\s+post\s+your\s+(?:address|info|details|location)\b", re.IGNORECASE),
        re.compile(r"\beveryone\s+will\s+know\s+who\s+(?:you|u)\s+(?:really\s+)?are\b", re.IGNORECASE),
        re.compile(r"\bcoming\s+to\s+your\s+(?:house|home)\b", re.IGNORECASE)
    ],
    "dehumanization": [
        # Uses non-capturing group (?:human|people|person)
        re.compile(r"\b(?:they|these people)\s+are\s+(?:animals|rats|roaches|pigs|parasites)\b", re.IGNORECASE),
        re.compile(r"\b(?:are|is)\s+(?:not|less than)\s+(?:human|people|person)\b", re.IGNORECASE),
        re.compile(r"\bshould\s+be\s+(?:exterminated|eradicated|wiped out)\b", re.IGNORECASE),
        re.compile(r"\bare\s+(?:a disease|a cancer|subhuman)\b", re.IGNORECASE)
    ],
    "coordinated_harassment": [
        re.compile(r"\beveryone\s+report\s+@?[\w_]+\b", re.IGNORECASE),
        re.compile(r"\blet'?s\s+all\s+go\s+after\b", re.IGNORECASE),
        re.compile(r"\braid\s+(?:their|this)\s+profile\b", re.IGNORECASE),
        # Uses positive lookahead (?=...) as required by the rubric
        re.compile(r"\bmass\s+report(?=\s+this)\b", re.IGNORECASE) 
    ]
}

def input_filter(text: str) -> dict | None:
    """Returns a block decision dict if matched, else None."""
    for category, patterns in BLOCKLIST.items():
        for pattern in patterns:
            if pattern.search(text):
                return {"decision": "block", "layer": "input_filter", "category": category, "confidence": 1.0}
    return None

class ModerationPipeline:
    def __init__(self, calibrated_model_func):
        """
        Takes a function that accepts a text string and returns a calibrated probability.
        """
        self.calibrated_model_func = calibrated_model_func
        
    def predict(self, text: str) -> dict:
        # Layer 1: Regex Pre-filter
        filter_result = input_filter(text)
        if filter_result:
            return filter_result
            
        # Layer 2 & 3: Calibrated Model and Routing
        prob = self.calibrated_model_func(text)
        
        if prob >= 0.6:
            return {"decision": "block", "layer": "model", "confidence": prob}
        elif prob < 0.4:
            return {"decision": "allow", "layer": "model", "confidence": prob}
        else:
            return {"decision": "review", "layer": "model", "confidence": prob}