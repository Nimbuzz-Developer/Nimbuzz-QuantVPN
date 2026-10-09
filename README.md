# Nimbuzz QuantVPN - Post-Quantum VPN | Nepal Safe Zone

**Like Switzerland. Outside 14 Eyes. But No Data Retention.**

> $2.99/mo billed monthly. No annual trap. ∞ Unlimited Sessions. RAM-only. MLKEM 1024.

## Why Nepal > Switzerland > India

| Country | 14 Eyes? | Data Retention | Verdict |
|---------|----------|----------------|---------|
| **Nepal** | NO - Outside | NO mandatory law | **SAFE ZONE** - 28°N 84°E Himalayas |
| Switzerland | NO - Outside | YES - BÜPF 6 months + MLAT | Risk: retention |
| India | NO - Outside | YES - CERT-In 5 YEARS mandatory | NOT safe - major VPNs left India |

- **Switzerland:** Outside 14 Eyes but BÜPF requires 6-month retention, easy MLAT with US/EU.
- **India:** CERT-In 2022 directive forces VPNs to keep name, address, phone, email, IPs, purpose for 5 years + 180-day logs + report in 6 hrs. (Sources: thehackernews.com, TimesOfIndia)
- **Nepal:** Independent jurisdiction, no mandatory VPN retention, 147,516 km² between India & China, does NOT border Bangladesh.

14 Eyes = SIGINT Seniors Europe: USA, Canada, UK, Australia, NZ, Denmark, France, Netherlands, Norway, Germany, Belgium, Italy, Sweden, Spain. [Wikipedia - Five_Eyes#Fourteen_Eyes](https://en.wikipedia.org/wiki/Five_Eyes#Fourteen_Eyes)

## Post-Quantum Security: MLKEM 1024

- **MLKEM-1024 + X25519 hybrid** - NIST Level 5
- RSA/ECC will break with quantum computers. MLKEM won't.
- Implementation: liboqs, auditable in `/crypto` folder.

## RAM-Only - No Logs Proof

All servers run on RAM. No disks.

**Dummy file test:**
```bash
ssh server
touch /tmp/proof.txt
ls /tmp/proof.txt # exists
sudo reboot
ssh server
ls /tmp/proof.txt # not found - RAM wiped


## Warrant Canary — Nimbuzz QuantVPN

**As of 2026-10-09:** No warrants, no searches, no gag orders.

**Next update:** 2026-11-09

**Signed:** Nimbuzz Team
