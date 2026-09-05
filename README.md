# SecureLogin
This project shows a demonstration of device-pinning for authentication that prevents an attacker from using a stolen session, cookie, or token by tying user sessions to a unique fingerprint of the device. 

Even if an attacker was able to exfiltrate a working session cookie, they would need to imitate values from your device such as:
- Graphics Processor Name
- Graphics Driver Version
- SSL/TLS extensions
- Browser and Browser Version

### The problem: Session Hijacking
Modern infostealers (malware that can exfiltrate cookies and tokens) can easily steal a user's authenticated session from infected machines. Once the attacker has the victim's session cookie, an attacker can:
- Impersonate the victim on a website or service
- Drain cryptocurrency wallets
- Fraudulently charge payment processors linked to the account
- Steal personal data
- Bypass MFA

This happens because when the attacker passes the stolen session cookie to the website or service, they see this request as authenticated and coming from the user.

**SecureLogin** solves this  by making sessions unusable outisde their original device context.

### How It Works:

#### 1. **Device Fingerprinting on Login**
When a user logs in, JavaScript generates a browser fingerprint using [IPQS](https://ipqualityscore.com/) by using the following values:
   - **Device ID** - unique hardware identifier
   - **Canvas hash** - GPU/driver/browser combination
   - **WebGL hash** - graphics capability signature
   - **Graphics card name** - GPU model
   - **SSL fingerprint** - browser's TLS cipher suite

These identifier values are hashed together into a single hardware identifier:
```php
$deviceID = sha1("device_id-canvas_hash-webgl_hash-graphics_card-ssl_fingerprint");
```
This hardware identifier is stored in the database, linking it to that session.

#### 2. **Session Validation on Every Important Request**
On the member/user only page (`index.php`), when the protected action is called:
- JavaScript re-triggers the IPQS fingerprinting library
- Takes the received `request_id` value from the IPQS response, and sends it to `/api.php` as a "heartbeat"
- Server requests the IPQS Postback API with the `request_id`, and marks the `request_id` as consumed.
- Server takes the values from the IPQS Postback API to calculate the hardware identifier again.
- **If it matches** -> request proceeds
- **If it doesn't match** -> session is immediately revoked and the user is redirected the the MFA page

#### 3. **Automatic Session Revocation**
```sql
UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP 
WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL
```
The session is marked as compromised and invalidated permanently.

#### 4. **Replay Attack Prevention**
Every fingerprint verification is tied to a unique `request_id` value returned from the IPQS fingerprinting library. To prevent an attacker from replaying captured fingerprint:
- Each `request_id` is marked as "consumed" in the database
- Reusing the same `request_id` fails immediately.
- Protects against: stolen API responses, intercepted network traffic

### Setup Instructions:

#### Prerequisites:
- PHP 7.4+ (with cURL)
- MySQL / MariaDB

#### 1. Database setup:
Import the sql file into your database:
```bash
mysql -u root -p < db.sql
```

Creates three tables:
- `users` - stores email & password (hashed)
- `user_sessions` - tracks session-to-device mappings, can be used to allow the user to revoke remote sessions they dont recognize
- `consumed_request_ids` - prevents replay attacks

#### 2. Configuration:
Edit `Library/Config/Config.php`:
- Add your Database Credentials
- Add your IPQS Device Tracker key and domain
- Add your IPQS API Key

#### 3. Create a Test user:
Registration is not implemented in this example, to insert a user:

```php
// Run this once to create a test account
$email = 'test@example.com';
$password = password_hash('SecurePassword123!', PASSWORD_DEFAULT);
 
// Insert into `users` table:
// mysql> INSERT INTO users (email, password) VALUES ('test@example.com', '$2y$...');
```
**Test MFA Code**: `000000` (hardcoded for demo)

### Security Layers
| Layer | Mechanism | Protects Against |
|-------|-----------|------------------|
| **Device Fingerprint** | Browser/GPU/hardware hash | Cross-device fraud |
| **Replay Prevention** | Consumed request IDs | Replaying stolen fingerprints |
| **CSRF Tokens** | Rotating token on every response | CSRF attacks on forms/APIs |
| **Session Revocation** | Immediate marking on mismatch | Continued unauthorized access |
| **MFA** | User must complete before access | Unauthorized login during hijack |
