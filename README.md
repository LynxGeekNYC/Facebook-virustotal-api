# Facebook-virustotal-api

### GitHub Repository Description:
**FaceBook Malicious URL Detector and Auto-Ban System**

This Python framework integrates Facebook group moderation using GraphAPI with VirusTotal's API to automatically detect and handle malicious URLs shared in Facebook groups. The framework scans for URLs posted by users, verifies them using VirusTotal, and automatically bans users identified as sharing harmful or suspicious links. This tool is designed to help group admins prevent malicious activity, safeguard their groups, and ensure a safer online environment.

---

### How It Works:

1. **Facebook API Integration**:
   - The script connects to your Facebook group using Facebook’s Graph API.
   - It fetches recent posts and scans for URLs shared within the group.

2. **VirusTotal API**:
   - When a URL is found, it is sent to VirusTotal's API for analysis.
   - VirusTotal checks the URL against multiple antivirus databases and reports whether the URL is malicious, suspicious, or clean.

3. **Auto-Moderation**:
   - If VirusTotal reports the URL as malicious or suspicious, the framework immediately flags the user.
   - The script then automatically bans the user from the group using Facebook's API.
   - An optional logging feature records the user details and URL for future reference.

4. **Logging and Notifications**:
   - The system can log banned users and URLs in a separate file or database.
   - Admins can also set up notifications (via email or Facebook Messenger) for when a user is banned for sharing malicious links.

5. **Customization**:
   - The framework allows group admins to customize thresholds (e.g., ban users for suspicious URLs or only malicious ones).
   - Admins can adjust scan intervals and configure the types of URLs to watch out for.

### Features:
- Automated URL detection in Facebook groups.
- VirusTotal API integration for URL safety checks.
- Automatic user banning based on URL threat levels.
- Logging and notification system for group admins.
- Customizable moderation rules and scan frequencies.

This script aims to assist Facebook group admins by automating the detection and removal of malicious content, improving group security without constant manual oversight.

# Was this script helpful to you? Please donate:

PayPal: alex@alexandermirvis.com

CashApp / Venmo: LynxGeekNYC

BitCoin: bc1q8sthd96c7chhq5kr3u80xrxs26jna9d8c0mjh7
