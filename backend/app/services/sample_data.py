"""Sample phishing and legitimate email data for ChromaDB initialization."""

PHISHING_SAMPLES = [
    {
        "id": "phish_001",
        "subject": "Urgent: Your PayPal account has been limited",
        "from": "security@paypa1-alerts.com",
        "body": """Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been limited.

To restore your account access, you must verify your information within 24 hours.

Click here to verify: http://paypa1-secure-login.tk/verify

If you do not verify, your account will be permanently suspended.

PayPal Security Team""",
        "urls": ["http://paypa1-secure-login.tk/verify"],
        "campaign": "PayPal Credential Harvesting Campaign",
        "attack_type": "credential_harvesting",
        "risk_level": "CRITICAL",
        "description": "Classic PayPal phishing with typosquatted domain and urgency tactics",
        "source": "demo_data",
    },
    {
        "id": "phish_002",
        "subject": "Your Microsoft Account: Action Required",
        "from": "noreply@micros0ft-account.com",
        "body": """Hello,

Your Microsoft account password is about to expire. To continue using Microsoft services, 
you must update your password immediately.

Sign in to your account here: https://micros0ft-login.xyz/update-password

This link expires in 12 hours. Failure to act will result in account suspension.

Microsoft Account Team""",
        "urls": ["https://micros0ft-login.xyz/update-password"],
        "campaign": "Microsoft Credential Phishing",
        "attack_type": "account_takeover",
        "risk_level": "HIGH RISK",
        "description": "Microsoft account phishing with character substitution in domain",
        "source": "demo_data",
    },
    {
        "id": "phish_003",
        "subject": "INVOICE #INV-2024-8821 - Payment Required",
        "from": "billing@trusted-invoices-corp.tk",
        "body": """Dear Accounts Payable,

Please find attached invoice #INV-2024-8821 for $8,750.00 for consulting services rendered.

Payment is due within 24 hours to avoid late fees and service interruption.

Wire transfer details:
Bank: First National Bank
Account: 847392018
Routing: 021000021

For questions, contact: billing@trusted-invoices-corp.tk

URGENT: Do not forward this email. Process payment today.""",
        "urls": [],
        "campaign": "BEC Invoice Fraud Campaign",
        "attack_type": "invoice_fraud",
        "risk_level": "HIGH RISK",
        "description": "Business Email Compromise targeting accounts payable with fake invoices",
        "source": "demo_data",
    },
    {
        "id": "phish_004",
        "subject": "Your Amazon order has been cancelled - Verify payment",
        "from": "orders@amazon-customer-support.link",
        "body": """Hello,

Your recent Amazon order has been cancelled due to a payment issue.

Order #114-8847291-9927543
Total: $289.99

To reinstate your order and prevent account suspension, please verify your payment information immediately:

https://amazon-verify-payment.click/account/billing

Your Amazon Prime membership is also at risk if you do not act within 48 hours.

Amazon Customer Service""",
        "urls": ["https://amazon-verify-payment.click/account/billing"],
        "campaign": "Amazon Payment Phishing",
        "attack_type": "credential_harvesting",
        "risk_level": "CRITICAL",
        "description": "Amazon phishing using order cancellation fear and account suspension threat",
        "source": "demo_data",
    },
    {
        "id": "phish_005",
        "subject": "LinkedIn: Your account will be deactivated",
        "from": "security@linkedin-alerts.pw",
        "body": """Dear LinkedIn Member,

We have detected suspicious login activity on your account. To protect your data,
we have temporarily restricted access.

To restore access within the next 12 hours, please verify your identity:
http://linkedin-account-restore.tk/verify?id=XJ92K

Failure to verify will result in permanent account deletion and loss of all connections.

LinkedIn Security Team
security@linkedin.com""",
        "urls": ["http://linkedin-account-restore.tk/verify?id=XJ92K"],
        "campaign": "LinkedIn Account Suspension Phishing",
        "attack_type": "social_engineering",
        "risk_level": "HIGH RISK",
        "description": "LinkedIn phishing with false sender address in email body",
        "source": "demo_data",
    },
    {
        "id": "phish_006",
        "subject": "CEO Request: Urgent Wire Transfer Needed",
        "from": "john.smith.ceo@company-executives.co",
        "body": """Hi,

I need you to process an urgent wire transfer today. I am in a meeting and cannot be reached by phone.

Please transfer $47,500 to:
Beneficiary: Global Consulting Partners Ltd
Bank: HSBC London
IBAN: GB29NWBK60161331926819
Reference: CONF-2024-Q4

This is time sensitive. Do not discuss with anyone — confidential M&A activity.

Please confirm when done.

John Smith
CEO""",
        "urls": [],
        "campaign": "CEO Fraud / BEC",
        "attack_type": "ceo_fraud",
        "risk_level": "CRITICAL",
        "description": "Classic CEO fraud requesting urgent wire transfer with secrecy demand",
        "source": "demo_data",
    },
    {
        "id": "phish_007",
        "subject": "Your Apple ID has been used to sign in from a new device",
        "from": "appleid@apple-account-security.com",
        "body": """Apple ID Security Alert

Your Apple ID was used to sign in to iCloud on an iPhone 15 in Russia at 3:47 AM.

If you did not authorize this, click the link below immediately to secure your account:
https://apple-id-secure.pw/lockout?session=8Xn2kQ

If you don't respond within 1 hour, your Apple ID will be suspended to prevent unauthorized access.

Apple Security""",
        "urls": ["https://apple-id-secure.pw/lockout?session=8Xn2kQ"],
        "campaign": "Apple ID Credential Phishing",
        "attack_type": "account_takeover",
        "risk_level": "CRITICAL",
        "description": "Apple ID phishing exploiting fear of unauthorized access from foreign country",
        "source": "demo_data",
    },
    {
        "id": "phish_008",
        "subject": "DHL: Package delivery failed - Action required",
        "from": "delivery@dhl-tracking-alerts.ml",
        "body": """DHL Express Delivery Notification

We attempted to deliver your package today but were unable to complete delivery.

Tracking: 1Z999AA10123456784
Package value: $342.00

To reschedule delivery, a customs clearance fee of $2.49 is required:
http://dhl-customs-payment.tk/pay?ref=1Z999AA1

Payment must be made within 24 hours or the package will be returned to sender.

DHL Express Customer Service""",
        "urls": ["http://dhl-customs-payment.tk/pay?ref=1Z999AA1"],
        "campaign": "DHL Parcel Delivery Scam",
        "attack_type": "smishing_email",
        "risk_level": "HIGH RISK",
        "description": "Fake delivery notification requesting payment on suspicious domain",
        "source": "demo_data",
    },
    {
        "id": "phish_009",
        "subject": "Netflix: Your payment declined - Update billing",
        "from": "billing@netflix-payments.xyz",
        "body": """Dear Netflix Member,

We were unable to process your payment for this month's subscription.

To prevent service interruption, please update your billing information:
https://netflix-billing-update.xyz/account

You have 48 hours before your account is suspended.

Netflix Billing Team""",
        "urls": ["https://netflix-billing-update.xyz/account"],
        "campaign": "Netflix Billing Phishing",
        "attack_type": "credential_harvesting",
        "risk_level": "HIGH RISK",
        "description": "Netflix billing phishing targeting payment credentials",
        "source": "demo_data",
    },
    {
        "id": "phish_010",
        "subject": "IRS: Tax Refund Ready - Claim Now",
        "from": "refunds@irs-tax-refund.cc",
        "body": """Internal Revenue Service
Department of the Treasury

You are eligible for a tax refund of $1,847.00 for the tax year 2023.

To claim your refund, provide your information at:
http://irs-refund-claim.pw/2023/claim

You must claim within 5 business days or the refund will be forfeited.

Note: The IRS will never ask for payment in gift cards, wire transfers, or cryptocurrency.

IRS Tax Refund Department""",
        "urls": ["http://irs-refund-claim.pw/2023/claim"],
        "campaign": "IRS Tax Refund Scam",
        "attack_type": "government_impersonation",
        "risk_level": "CRITICAL",
        "description": "IRS impersonation scam; note the ironic disclaimer about IRS never asking for such payment",
        "source": "demo_data",
    },
]

LEGITIMATE_SAMPLES = [
    {
        "id": "legit_001",
        "subject": "CS Department Newsletter - November 2024",
        "from": "newsletter@cs.university.edu",
        "body": """Dear Students and Faculty,

Welcome to the November edition of the CS Department newsletter.

This month's highlights:
- Annual Research Symposium: December 12-13
- New GPU cluster available for research projects
- Job fair with 40+ tech companies: November 29
- Deadline for spring semester registration: December 1

For more information, visit our department portal at cs.university.edu/news

Best regards,
CS Department Communications""",
        "urls": ["https://cs.university.edu/news"],
        "campaign": "Legitimate University Newsletter",
        "attack_type": "none",
        "risk_level": "SAFE",
        "description": "Legitimate university department newsletter",
        "source": "demo_data",
    },
    {
        "id": "legit_002",
        "subject": "Your GitHub pull request was merged",
        "from": "noreply@github.com",
        "body": """Hi @developer,

Your pull request #142 "Fix authentication bug in user service" was merged into main.

View the merged PR: https://github.com/org/repo/pull/142

Merged by: Jane Smith (@jsmith)
Commits: 3 commits, +127 -45 lines

Repository: org/repo
Branch: main

You're receiving this because you authored this pull request.
Unsubscribe: https://github.com/notifications/unsubscribe

GitHub""",
        "urls": ["https://github.com/org/repo/pull/142"],
        "campaign": "Legitimate GitHub Notification",
        "attack_type": "none",
        "risk_level": "SAFE",
        "description": "Standard GitHub pull request merge notification",
        "source": "demo_data",
    },
    {
        "id": "legit_003",
        "subject": "Chase: Your statement is ready",
        "from": "no-reply@chase.com",
        "body": """Your Chase Freedom statement is ready.

Account ending in 4721
Statement period: Oct 1 - Oct 31, 2024
Minimum payment due: $35.00
Due date: November 25, 2024
Balance: $1,247.82

Sign in to view your complete statement at chase.com

Chase Bank, N.A. Member FDIC
Equal Housing Lender""",
        "urls": ["https://www.chase.com"],
        "campaign": "Legitimate Bank Statement Notification",
        "attack_type": "none",
        "risk_level": "SAFE",
        "description": "Legitimate bank statement notification from official domain",
        "source": "demo_data",
    },
    {
        "id": "legit_004",
        "subject": "Meeting invitation: Q4 Planning Session",
        "from": "calendar@company.com",
        "body": """You have been invited to a meeting.

Q4 Planning Session
Date: Thursday, November 14, 2024
Time: 2:00 PM - 4:00 PM EST
Location: Conference Room B / Teams link

Organizer: Sarah Johnson (sarah.johnson@company.com)
Attendees: Engineering Team (15 people)

Agenda:
1. Q3 retrospective (30 min)
2. Q4 roadmap review (45 min)
3. Resource planning (30 min)
4. Open discussion (15 min)

Teams link: https://teams.microsoft.com/l/meetup-join/...

Calendar | Company Intranet""",
        "urls": ["https://teams.microsoft.com/l/meetup-join/..."],
        "campaign": "Legitimate Meeting Invitation",
        "attack_type": "none",
        "risk_level": "SAFE",
        "description": "Standard corporate meeting invitation",
        "source": "demo_data",
    },
    {
        "id": "legit_005",
        "subject": "Your order has shipped - Amazon Order #114-4729182",
        "from": "shipment-tracking@amazon.com",
        "body": """Hello,

Your order has shipped!

Order #114-4729182
Estimated delivery: Wednesday, November 13
Tracking: 1Z999AA10123456784

Items in this shipment:
1x USB-C Hub 7-in-1 - $34.99

Track your package at amazon.com/orders

Thank you for shopping with us.
Amazon Customer Service""",
        "urls": ["https://www.amazon.com/orders"],
        "campaign": "Legitimate Amazon Shipping Notification",
        "attack_type": "none",
        "risk_level": "SAFE",
        "description": "Legitimate Amazon shipping notification from official domain",
        "source": "demo_data",
    },
]

ALL_SAMPLES = PHISHING_SAMPLES + LEGITIMATE_SAMPLES
