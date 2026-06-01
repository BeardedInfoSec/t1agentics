# T1 Agentics - Multi-Factor Authentication (MFA) Setup Guide

Protect your account with Time-based One-Time Passwords (TOTP).

---

## What is MFA?

Multi-Factor Authentication adds an extra layer of security to your account. After entering your password, you'll also need to enter a 6-digit code from your authenticator app. This means even if someone steals your password, they can't access your account without your phone.

---

## Supported Authenticator Apps

Any TOTP-compatible app works. We recommend:

| App | Platform | Download |
|-----|----------|----------|
| **Google Authenticator** | iOS, Android | App Store / Play Store |
| **Microsoft Authenticator** | iOS, Android | App Store / Play Store |
| **Authy** | iOS, Android, Desktop | authy.com |
| **1Password** | All platforms | 1password.com |

---

## Setting Up MFA

### Step 1: Navigate to MFA Settings

1. Click your **username** in the top-right corner
2. Select **Profile**
3. Go to the **Security** section
4. Click **Enable Two-Factor Authentication**

### Step 2: Scan the QR Code

1. A QR code will appear on screen
2. Open your authenticator app
3. Tap **Add Account** or the **+** button
4. Scan the QR code with your phone's camera

**Can't scan?** Click "Enter manually" and type the secret key into your app.

### Step 3: Verify Your Setup

1. Your authenticator app will show a 6-digit code that changes every 30 seconds
2. Enter the current code in the verification field
3. Click **Verify**
4. MFA is now active!

### Step 4: Save Your Recovery Codes

**IMPORTANT**: You'll receive 8 one-time recovery codes. Save them somewhere safe!

- Print them and store in a secure location
- Save them in a password manager
- Each code can only be used **once**
- If you lose your authenticator and all recovery codes, contact your admin

---

## Logging In with MFA

1. Enter your **username** and **password** as usual
2. You'll see a prompt for your **6-digit code**
3. Open your authenticator app and enter the current code
4. Click **Verify** to complete login

**Tip**: Codes change every 30 seconds. If your code is about to expire, wait for the next one.

---

## Using Recovery Codes

If you can't access your authenticator app:

1. On the MFA prompt, click **"Use a recovery code"**
2. Enter one of your saved recovery codes
3. The code will be consumed (can't be reused)
4. Set up your authenticator app again as soon as possible

---

## Disabling MFA

1. Go to **Profile > Security**
2. Click **Disable Two-Factor Authentication**
3. Enter your password to confirm
4. MFA will be removed from your account

---

## FAQ

**Q: What if I get a new phone?**
A: Disable MFA before switching phones, then re-enable it on your new device. Or use a recovery code to log in and re-setup.

**Q: Why are my codes not working?**
A: Check that your phone's clock is accurate. TOTP codes depend on synchronized time. Enable "Automatic date & time" in your phone settings.

**Q: Can I have MFA on multiple devices?**
A: When setting up MFA, scan the QR code on all devices you want to use before clicking Verify.

**Q: Is MFA required?**
A: MFA is optional but strongly recommended, especially for admin accounts. Your organization may enforce it via policy.

---

*T1 Agentics - Autonomous Security Operations*
*Licensed under the Apache License, Version 2.0. See the root LICENSE file.*
