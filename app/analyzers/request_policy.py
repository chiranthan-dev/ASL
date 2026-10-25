"""Request Policy Gate — is this *purpose* permissible?

Every other analyzer in ASL answers "is this action dangerous?". That question
has a blind spot, and it is a serious one: an agent asked to break into a server
may propose nothing more alarming than a web search. The mechanics are harmless,
the request is not, and a pipeline that only reasons about capabilities and
resources will allow it at risk ~15.

This stage asks the other question. It classifies the *stated request* against
categories of prohibited purpose, independently of how benign the resulting tool
call looks.

    "HACK INTO SERVER"                        -> UNAUTHORIZED_ACCESS  (prohibited)
    "get messages of my colleagues"           -> SURVEILLANCE         (prohibited)
    "find me nsfw pictures"                   -> SEXUAL_CONTENT       (prohibited)
    "how do I protect against SQL injection"  -> no finding           (defensive)

## Why this does not contradict prompt-injection resistance

ASL deliberately refuses to let the prompt *lower* risk or vouch for a call,
because under injection the prompt is exactly the thing that lies. This gate is
the mirror image, and the asymmetry is the whole point:

    prompt evidence is admissible only in the direction of caution.

It may raise risk, require a human, or block. It may never reduce risk or
authorize. An attacker who injects text that causes a *refusal* has achieved a
denial of service at worst — never an escalation. So reading the prompt for
hostile purpose is safe in a way that reading it for reassurance never is.

## What this is not

A regex list is a floor, not a ceiling. A determined user who paraphrases
("retrieve correspondence belonging to coworkers") will evade these patterns.
This raises the cost of a hostile request; it does not close the class. The
`PurposeClassifier` interface exists so a trained classifier can replace the
deterministic matcher without touching the engine — that is the real answer, and
it is future work, not a claim made here.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.models.enums import StrEnum


class PolicySeverity(StrEnum):
    NONE = "NONE"
    RESTRICTED = "RESTRICTED"
    PROHIBITED = "PROHIBITED"


SEVERITY_RISK: dict[PolicySeverity, float] = {
    PolicySeverity.NONE: 0.0,
    PolicySeverity.RESTRICTED: 62.0,
    PolicySeverity.PROHIBITED: 96.0,
}


@dataclass
class PolicyFinding:
    category: str
    severity: PolicySeverity
    matched: str
    why: str


@dataclass
class PolicyAssessment:
    severity: PolicySeverity = PolicySeverity.NONE
    category: str | None = None
    risk: float = 0.0
    confidence: float = 0.0
    findings: list[PolicyFinding] = field(default_factory=list)
    explanation: str = ""
    mitigated: bool = False

    @property
    def fired(self) -> bool:
        return self.severity is not PolicySeverity.NONE

    def as_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "risk": self.risk,
            "confidence": self.confidence,
            "mitigated": self.mitigated,
            "explanation": self.explanation,
            "findings": [
                {"category": f.category, "severity": f.severity.value,
                 "matched": f.matched, "why": f.why}
                for f in self.findings
            ],
        }


Rule = tuple[str, PolicySeverity, str, str]

RULES: tuple[Rule, ...] = (
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\bhack(ing|ed)?\s+(in)?to\b|\bhack\s+(a|the|this|that|my\s+\w+'?s?)\s*\w*\s*(server|system|account|network|site|website|database|pc|computer|wifi)\b",
     "requests intrusion into a system"),
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\b(break|breaking|broke|breaks)\s+in(\s*to)?\b|\bget\s+(unauthori[sz]ed|illegal)\s+(access|entry)\b|"
     r"\bunauthori[sz]ed\s+(access|entry)\s+to\b|"
     r"\bget\s+(admin|administrator|root|superuser)\s+(access|rights|privileges)\s+(on|to)\b.{0,30}"
     r"\b(network|server|system|machine|box|computer|panel|portal)\b",
     "requests unauthorised entry"),
    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\b(record|log|capture|send|save|upload)\w*\b.{0,20}\b(every|all|each)\s+(keystroke|key\s*stroke|keypress|key\s*press)e?s?\b",
     "requests capturing a person's keystrokes"),
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\bbypass\b.{0,25}\b(login|auth\w*|password|2fa|mfa|security|paywall|licen[cs]e|drm)\b",
     "requests circumvention of an access control"),
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\b(crack\w*|brute[\s-]?forc\w*|bypass\w*)\b.{0,25}\bpasswords?\b|\bpassword\s+crack\w*",
     "requests password cracking"),
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\bexploit\b.{0,30}\b(server|system|network|database|vulnerab\w+|cve-)\b|\bprivilege\s+escalation\b|\bget\s+root\s+(on|access)\b",
     "requests exploitation of a system"),
    ("UNAUTHORIZED_ACCESS", PolicySeverity.PROHIBITED,
     r"\b(ddos|denial[\s-]of[\s-]service)\b.{0,20}\b(attack|them|the\s+\w+)\b|\blaunch\s+a\s+ddos\b|\bdeface\b",
     "requests a disruptive attack"),

    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\b(get|read|access|retrieve|fetch|see|check|show|pull|copy|extract)\b.{0,45}"
     r"\b(messages?|emails?|mails?|chats?|texts?|dms?|conversations?|files?|photos?|documents?|browsing\s+history|screen)\b"
     r".{0,45}\b(colleague|coworker|co-worker|classmate|employee|friend|wife|husband|partner|girlfriend|boyfriend|"
     r"ex|neighbou?r|someone\s+else|other\s+people|another\s+(person|user)|their|his|her|thier)\b",
     "requests another person's private content"),
    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\b(get|read|access|retrieve|fetch|see|check|show|pull|copy|extract|open|look\s+at)\b.{0,25}"
     r"\b(colleague|coworker|co-worker|classmate|employee|friend|wife|husband|partner|girlfriend|"
     r"boyfriend|neighbou?r|someone\s+else|another\s+(person|user))(?:'s|s')?\b.{0,25}"
     r"\b(messages?|emails?|mails?|chats?|texts?|dms?|conversations?|files?|photos?|documents?|"
     r"browsing\s+history|screen|account|inbox)\b",
     "requests a named third party's private content"),
    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\bspy\s+on\b|\bkeylog\w*|\bstalk\b|\bsecretly\s+(monitor|record|watch|track)\b|"
     r"\bmonitor\b.{0,30}\bwithout\b.{0,20}\b(know|knowing|consent|permission)\b",
     "requests covert monitoring of a person"),
    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\btrack\b.{0,25}\b(location|whereabouts)\b.{0,10}\bof\s+(someone|somebody|him|her|them|"
     r"my\s+(?!own\b|lost\b|stolen\b|phone\b|car\b|bag\b|parcel\b|package\b|laptop\b|device\b)\w+)|"
     r"\btrack\b.{0,25}\b(his|her|their|someone'?s)\s+(phone|location|whereabouts)\b|"
     r"\bfind\s+out\s+where\b.{0,20}\b(he|she|they|someone)\s+(is|lives)\b",
     "requests tracking a person"),
    ("SURVEILLANCE", PolicySeverity.PROHIBITED,
     r"\bfrom\s+(their|his|her)\s+(pcs?|computers?|laptops?|phones?|devices?|machines?)\b",
     "targets another person's device"),

    ("CREDENTIAL_THEFT", PolicySeverity.PROHIBITED,
     r"\b(steal|dump|harvest|exfiltrate|siphon|scrape)\b.{0,30}\b(password|credential|token|api\s*key|private\s*key|hash|session|cookie)\b",
     "requests theft of credentials"),
    ("CREDENTIAL_THEFT", PolicySeverity.PROHIBITED,
     r"\bphish\w*|\bcredential\s+harvest\w*|\bfake\s+login\s+page\b",
     "requests a phishing capability"),
    ("DATA_THEFT", PolicySeverity.PROHIBITED,
     r"\b(steal|exfiltrate|leak|smuggle)\b.{0,30}\b(data|records?|database|customer|client|patient|files?)\b",
     "requests theft of data"),

    ("MALWARE", PolicySeverity.PROHIBITED,
     r"\b(write|create|build|make|generate|code|develop)\b.{0,30}"
     r"\b(malware|virus|ransomware|keylogger|trojan|botnet|rootkit|worm|spyware|backdoor|exploit\s+kit)\b",
     "requests creation of malicious software"),
    ("MALWARE", PolicySeverity.PROHIBITED,
     r"\bransomware\b|\bencrypt\b.{0,25}\bfiles\b.{0,25}\b(ransom|payment|bitcoin)\b",
     "requests ransomware"),

    ("CSAM", PolicySeverity.PROHIBITED,
     r"\b(child|minor|kid|teen|underage|preteen|loli)\w*\b.{0,25}\b(porn|nude|naked|sexual|explicit|nsfw)\b|"
     r"\b(porn|nude|naked|sexual|explicit|nsfw)\b.{0,25}\b(child|minor|kid|teen|underage|preteen)\w*\b",
     "requests sexual content involving minors"),
    ("SEXUAL_CONTENT", PolicySeverity.PROHIBITED,
     r"\bnsfw\b|\bporn\w*|\bxxx\b|\b(nude|naked)\s+(pic|pics|photo|photos|image|images|video)\w*|"
     r"\bsexually\s+explicit\b|\bexplicit\s+(adult\s+)?(image|photo|picture|video|content|material)\w*|"
     r"\badult\s+(image|photo|picture|video|content|material)\w*",
     "requests sexual content, which this assistant does not retrieve"),

    ("HARASSMENT", PolicySeverity.PROHIBITED,
     r"\bdoxx?(ing|ed)?\b|\bharass\w*|\bblackmail\w*|\bthreaten\b.{0,25}\b(him|her|them|someone)\b|"
     r"\bget\s+revenge\s+on\b|\bruin\s+(his|her|their)\s+(life|career|reputation)\b",
     "requests targeting or abusing a person"),

    ("FRAUD", PolicySeverity.PROHIBITED,
     r"\bimpersonat\w*|\bpretend\s+to\s+be\b.{0,25}\b(bank|police|admin|ceo|hr|support|government)\b|"
     r"\b(forge|fake)\b.{0,20}\b(invoice|receipt|id|identity|signature|document|passport)\b",
     "requests impersonation or forgery"),

    ("EVASION", PolicySeverity.PROHIBITED,
     r"\b(delete|clear|wipe|erase|disable|scrub|remove|turn\s+off|switch\s+off)\b.{0,25}"
     r"\b(audit\s*(trail|logs?|logging)?|access\s+logs?|server\s+logs?|system\s+logs?|security\s+logs?|monitoring|"
     r"evidence|traces?)\b|"
     r"\b(delete|clear|wipe|erase|disable|scrub|remove|turn\s+off)\b.{0,25}\b(logs?|logging|history)\b"
     r".{0,40}\b(so\s+(nobody|no\s+one|they\s+can'?t)|after\s+i|before\s+i|from\s+the\s+(server|system)|"
     r"was\s+there|of\s+my\s+(login|access|activity|visit))\b|"
     r"\bcover\s+(my|our|his|her|their)\s+tracks\b|\bavoid\s+detection\b|\bwithout\s+being\s+(detected|logged|noticed|seen)\b",
     "requests destruction of the record or evasion of monitoring"),
    ("EVASION", PolicySeverity.PROHIBITED,
     r"\b(disable|turn\s+off|bypass|get\s+around|circumvent)\b.{0,30}"
     r"\b(antivirus|firewall|security\s+layer|asl|safety|guardrails?|content\s+filter)\b",
     "requests disabling the security controls"),

    ("PHYSICAL_HARM", PolicySeverity.PROHIBITED,
     r"\b(make|build|synthesi[sz]e|create)\b.{0,30}\b(bomb|explosive|nerve\s+agent|bioweapon|meth|fentanyl)\b|"
     r"\bhow\s+to\s+(kill|poison)\s+(someone|a\s+person|him|her|them)\b",
     "requests assistance with serious physical harm"),

    ("SECURITY_TOOLING", PolicySeverity.RESTRICTED,
     r"\b(port\s*scan|nmap|metasploit|sqlmap|burp\s+suite|reverse\s+shell|payload\s+generator)\b",
     "requests offensive security tooling"),
    ("BULK_PERSONAL_DATA", PolicySeverity.RESTRICTED,
     r"\b(scrape|collect|compile|harvest)\b.{0,30}\b(emails?|phone\s+numbers?|addresses|personal\s+(data|information)|profiles)\b",
     "requests bulk collection of personal data"),
    ("MASS_MESSAGING", PolicySeverity.RESTRICTED,
     r"\b(mass|bulk)\s+(email|message|dm)\w*|\bspam\b.{0,20}\b(everyone|list|contacts)\b",
     "requests bulk unsolicited messaging"),
)


OTHER_PARTY = (
    r"(?:\b(?:my|our|the|a|this|that|his|her|their)\s+(?:old\s+|new\s+|ex-?)?)?"
    r"\b(?:manager|boss|roommate|flatmate|housemate|girlfriend|boyfriend|wife|husband|partner|ex|"
    r"sister|brother|mother|father|mom|mum|dad|daughter|son|teenager|child|kid|neighbou?r|"
    r"colleague|coworker|co-worker|classmate|teammate|teacher|professor|lecturer|landlord|tenant|"
    r"employee|employer|rival|competitor|friend|admin|administrator|ceo|director|supervisor|"
    r"someone\s+else|somebody\s+else|another\s+(?:person|user)|other\s+people)"
    r"(?:'s|s'|’s)"
)
PRIVATE_ASSET = (
    r"\b(?:e-?mails?|inbox|accounts?|messages?|chats?|texts?|whatsapp|dms?|calls?|voicemail|"
    r"photos?|pictures?|files?|documents?|drive|cloud|laptop|phone|computer|pc|webcam|camera|"
    r"location|whereabouts|password|passcode|pin|login|credentials?|bank|instagram|facebook|"
    r"snapchat|social\s+media|records?|diary|notes|browser|history)\b"
)
ACQUIRE = (
    r"\b(?:log\s*(?:in|into|in\s+to)|sign\s+in(?:to)?|access|open|read|copy|pull|get|grab|take\s+over|"
    r"take|download|see|look\s+at|view|check|sneak|listen\s+to|guess|crack|figure\s+out|work\s+out|"
    r"obtain|retrieve|monitor|track|watch|record|hijack|steal)\b"
)
COVERT = (
    r"\bwithout\s+(?:(?:him|her|them|their|his|anyone|anybody|the\s+\w+|my\s+\w+)\s+)?"
    r"(?:knowing|knowledge|noticing|finding\s+out|asking|permission|consent|approval|authori[sz]ation|"
    r"being\s+(?:seen|noticed|caught))\b|"
    r"\bwithout\s+(?:asking|telling)\s+(?:him|her|them)\b|"
    r"\bwhile\s+(?:he|she|they)\s+(?:is|are|'s|'re)\s+(?:out|away|asleep|not\s+looking)\b|"
    r"\b(?:secretly|covertly|discreetly|quietly|undetected)\b|\bbehind\s+(?:his|her|their)\s+back\b|"
    r"\bso\s+(?:nobody|no\s+one|they\s+don'?t)\s+(?:sees?|knows?|notices?|finds?\s+out)\b|"
    r"\bwith\s+(?:someone|somebody)\s+else'?s\s+(?:account|login|password|credentials?)\b"
)
ENTRY = (
    r"\b(?:log\s*(?:in|into|in\s+to)|sign\s+in(?:to)?|get\s+(?:into|past|in)|access|enter|"
    r"take\s+over|gain\s+access|get\s+(?:admin|root)\s+access)\b"
)
LOCATE_PERSON = (
    r"\b(?:find|figure\s+out|work\s+out|get|look\s+up|track\s+down|dig\s+up)\b.{0,30}"
    r"(?:\bhome\s+address(?:es)?\s+(?:of|for)\b|\bwhere\s+(?:my\s+\w+|he|she|they|this\s+\w+)\s+lives?\b|"
    r"\bpersonal\s+details\b)"
)


def _compositional_findings(text: str) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    covert = re.search(COVERT, text, re.I)

    m = re.search(ACQUIRE + r".{0,40}?" + OTHER_PARTY + r"[^.;]{0,30}?" + PRIVATE_ASSET, text, re.I)
    if m:
        findings.append(PolicyFinding(
            category="SURVEILLANCE",
            severity=PolicySeverity.PROHIBITED if covert else PolicySeverity.RESTRICTED,
            matched=m.group(0)[:80],
            why=("acquires another person's private asset"
                 + (" and says the owner is not to know" if covert else
                    "; no consent is stated, so a human should confirm"))))

    e = re.search(ENTRY, text, re.I)
    if e and covert:
        findings.append(PolicyFinding(
            category="UNAUTHORIZED_ACCESS", severity=PolicySeverity.PROHIBITED,
            matched=(e.group(0) + " … " + covert.group(0))[:80],
            why="requests entry to a system without the owner's sanction"))

    c = re.search(r"\b(?:password|passcode|pin|login|credentials?)\b", text, re.I)
    if c and re.search(ACQUIRE, text, re.I) and (re.search(OTHER_PARTY, text, re.I) or covert):
        findings.append(PolicyFinding(
            category="CREDENTIAL_THEFT", severity=PolicySeverity.PROHIBITED,
            matched=c.group(0), why="requests another person's credential"))

    loc = re.search(LOCATE_PERSON, text, re.I)
    if loc:
        findings.append(PolicyFinding(
            category="HARASSMENT", severity=PolicySeverity.PROHIBITED,
            matched=loc.group(0)[:80], why="requests locating or profiling a specific person"))
    return findings


MITIGATIONS: tuple[tuple[str, str], ...] = (
    (r"\bhow\s+(do\s+i|to|can\s+i)\s+(protect|defend|prevent|secure|harden|mitigate|stop|detect)\b",
     "framed as defence rather than attack"),
    (r"\b(is\s+it\s+legal|is\s+this\s+legal|what\s+are\s+the\s+risks|explain\s+how\b.{0,25}\bworks?)\b",
     "framed as an explanation rather than an act"),
    (r"\bfor\s+(my|our|a)\s+(thesis|dissertation|class|course|research|paper|assignment|exam|study)\b",
     "framed as academic work"),
    (r"\b(authori[sz]ed|permitted|approved)\s+(penetration\s+test|pentest|red\s+team|engagement)\b|"
     r"\bwith\s+(written\s+)?permission\b|\bctf\b|\bcapture\s+the\s+flag\b",
     "claims prior authorisation"),
    (r"\bon\s+(my|our)\s+own\s+(server|system|account|device|machine|network|laptop)\b",
     "claims the target is the requester's own"),
)

ABSOLUTE_CATEGORIES = frozenset({"CSAM", "MALWARE", "PHYSICAL_HARM", "HARASSMENT"})

CATEGORY_PRIORITY: tuple[str, ...] = (
    "CSAM", "PHYSICAL_HARM", "MALWARE", "CREDENTIAL_THEFT", "DATA_THEFT",
    "UNAUTHORIZED_ACCESS", "SURVEILLANCE", "HARASSMENT", "FRAUD", "EVASION",
    "SEXUAL_CONTENT", "SECURITY_TOOLING", "BULK_PERSONAL_DATA", "MASS_MESSAGING",
)


def _rank(finding: "PolicyFinding") -> tuple[float, int]:
    """Sort key: severity first, then category specificity."""
    priority = (CATEGORY_PRIORITY.index(finding.category)
                if finding.category in CATEGORY_PRIORITY else len(CATEGORY_PRIORITY))
    return (SEVERITY_RISK[finding.severity], -priority)


class PurposeClassifier(ABC):
    """Interface for classifying the purpose of a request."""

    name = "purpose"

    @abstractmethod
    def classify(self, prompt: str, conversation: list[str] | None = None) -> PolicyAssessment:
        ...


class PatternPurposeClassifier(PurposeClassifier):
    """Deterministic matcher. Explainable, fast, and evadable by paraphrase."""

    name = "pattern"

    def classify(self, prompt: str, conversation: list[str] | None = None) -> PolicyAssessment:
        text = " ".join([prompt or "", *(conversation or [])]).strip()
        if not text:
            return PolicyAssessment(explanation="no request text to evaluate")

        findings: list[PolicyFinding] = []
        for category, severity, pattern, why in RULES:
            match = re.search(pattern, text, re.I)
            if match:
                findings.append(PolicyFinding(
                    category=category, severity=severity,
                    matched=match.group(0)[:80], why=why,
                ))
        findings.extend(_compositional_findings(text))

        if not findings:
            return PolicyAssessment(explanation="no prohibited purpose detected in the request")

        worst = max(findings, key=_rank)
        severity = worst.severity
        mitigated = False

        if severity is PolicySeverity.PROHIBITED and worst.category not in ABSOLUTE_CATEGORIES:
            for pattern, reason in MITIGATIONS:
                if re.search(pattern, text, re.I):
                    severity = PolicySeverity.RESTRICTED
                    mitigated = True
                    worst = PolicyFinding(worst.category, severity, worst.matched,
                                          f"{worst.why}, but {reason}")
                    break

        risk = SEVERITY_RISK[severity]
        explanation = (
            f"{worst.category}: {worst.why} "
            f"(matched “{worst.matched}”)"
        )
        if mitigated:
            explanation += " — downgraded to a confirmation rather than a refusal"

        return PolicyAssessment(
            severity=severity,
            category=worst.category,
            risk=risk,
            confidence=0.88 if severity is PolicySeverity.PROHIBITED else 0.7,
            findings=findings,
            explanation=explanation,
            mitigated=mitigated,
        )


class RequestPolicyAnalyzer:
    """Pipeline-facing wrapper so the classifier can be swapped."""

    name = "request_policy"

    def __init__(self, classifier: PurposeClassifier | None = None) -> None:
        self.classifier = classifier or PatternPurposeClassifier()

    def analyze(self, prompt: str, conversation: list[str] | None = None) -> PolicyAssessment:
        return self.classifier.classify(prompt, conversation)
