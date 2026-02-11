# Mailvetter Engine v3.0

Mailvetter is a high-precision email verification microservice designed for the modern email landscape. It goes beyond simple SMTP checks to detect "Zombie" Office 365 accounts, disambiguate Catch-All domains, and verify digital footprints using deep OSINT probes.

## 🚀 Features

* **Deep SMTP Protocol:** VRFY support, Postmaster baseline checks, and Greylist detection.
* **Office 365 Logic:** Detects valid-but-blocked "Zombie" users (Teams identity without a SharePoint license).
* **Catch-All Resolution:** Converts "Unknown" catch-alls into "Likely Valid" or "Invalid" based on social proof.
* **Extended Socials:** Probes GitHub, Adobe, Gravatar, and Google Calendar.
* **Historical Proof:** Integrates with HIBP to confirm if an email has existed in past data breaches (Proof of Life).
* **Performance:** In-memory caching for DNS/Infrastructure prevents rate-limiting.

---

## 🛠️ Installation & Run

### Prerequisites
* Docker & Docker Compose
* (Optional) HaveIBeenPwned API Key for historical checks.

### Quick Start

1.  **Create a `.env` file** (Optional but recommended):
    ```env
    HIBP_API_KEY=your_key_here
    ```

2.  **Run via Docker Compose:**
    ```bash
    docker-compose up -d --build
    ```

3.  **Verify an Email:**
    ```bash
    curl "http://localhost:8080/verify?email=test@example.com"
    ```

---

## 📊 Score Interpretation

The engine returns a `score` between **0** and **100**.

| Score Range | Status | Meaning |
| :--- | :--- | :--- |
| **90 - 100** | `Safe` | **Guaranteed Deliverable.** SMTP confirmed or strong digital proof found. |
| **70 - 89** | `Safe` | **Likely Valid.** Catch-all with strong social footprint (GitHub, Adobe). |
| **60 - 69** | `Risky` | **Acceptable Risk.** Generic catch-all with some signals. |
| **1 - 59** | `Bad` | **Undeliverable or High Risk.** Invalid user, Zombie account, or empty catch-all. |
| **0** | `Invalid` | **Dead Address.** Hard bounce or domain does not exist. |

---

## 🚩 Legend: Score Details Flags

The `score_details` object explains *why* a score was given.

### 🟢 Base & Boosters (Positive Signals)

| Flag | Points | Description |
| :--- | :--- | :--- |
| `base_smtp_valid` | **90** | The SMTP server explicitly said "OK" (250). |
| `p0_vrfy_verified` | **99** | The server supported the VRFY command (Golden Ticket). |
| `p0_teams_identity` | **+15** | The email is registered on Microsoft Teams. |
| `p0_sharepoint_license`| **+60** | The user has an active Office 365 license (Strongest Proof). |
| `p0_calendar` | **+42.5**| The user has a public Google Calendar. |
| `p1_historical_breach`| **+45** | Email found in past data breaches (Proof of Human Existence). |
| `p2_github` | **+12** | Associated with a GitHub account. |
| `p2_adobe` | **+18.5**| Associated with an Adobe Creative Cloud account. |
| `p1_enterprise_sec` | **+15** | Protected by Proofpoint/Mimecast (High value corporate target). |

### 🟡 Catch-All Resolution (Disambiguation)

When a domain accepts all emails (`base_catch_all` = 30), we look for proofs to upgrade or downgrade it.

| Flag | Points | Description |
| :--- | :--- | :--- |
| `resolution_catchall_strong` | **+50** | **Likely Valid.** Found Calendar, SharePoint, or Breach History. |
| `resolution_catchall_medium` | **+25** | **Likely Human.** Found on GitHub, Adobe, or Teams. |
| `resolution_catchall_empty` | **-20** | **Likely Invalid.** Catch-all with absolutely zero digital footprint. |

### 🔴 Penalties (Negative Signals)

| Flag | Points | Description |
| :--- | :--- | :--- |
| `penalty_high_entropy` | **-20** | Username looks like a bot (e.g., `x8f921k@...`). |
| `penalty_role_account` | **-10** | Generic user (`admin`, `support`, `sales`). |
| `penalty_new_domain` | **-50** | Domain was registered less than 30 days ago (High Spam Risk). |

### 🧟 Office 365 "Zombie" Detection

Microsoft often returns "250 OK" for users who exist but are blocked/unlicensed. We fix this logic.

| Flag | Points | Description |
| :--- | :--- | :--- |
| `correction_o365_false_positive` | **-60** | **Correction.** We revoked the base 90 points because O365 lied about validity. |
| `penalty_o365_unlicensed` | **-20** | **Zombie.** Identity exists (Teams) but has no license (SharePoint). Cannot receive mail. |
| `penalty_o365_ghost` | **-30** | **Ghost.** SMTP said OK, but user has NO Microsoft footprint at all. |

---

## 📡 API Reference

**Endpoint:** `GET /verify`

**Parameters:**
* `email` (string): The email address to check.

**Response:**
```json
{
  "email": "riya.prajapati@ansibytecode.com",
  "score": 43,
  "status": "catch_all",
  "reachability": "bad",
  "score_details": {
    "base_smtp_valid": 90,
    "p0_teams_identity": 15,
    "p1_saas_usage": 10,
    "p2_dmarc": 4.5,
    "p2_spf": 3.5,
    "correction_o365_false_positive": -60,
    "penalty_o365_unlicensed": -20
  },
  "analysis": {
    "mx_provider": "office365",
    "has_teams_presence": true,
    "has_sharepoint": false,
    "is_catch_all": false
  }
}