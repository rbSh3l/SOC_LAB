# Incident Report 001 – SSH Brute Force / Password Spray Attempt

## 📌 Incident Summary

A suspected SSH brute-force/password spraying attack was identified during analysis of Linux authentication logs within the BOTSv3 dataset using Splunk Enterprise.

The investigation detected repeated failed login attempts against multiple common Linux usernames originating from a single source IP address.

---

# 🛠️ Detection Method

The following SPL query was used to identify suspicious authentication activity:

```spl
index=botsv3 sourcetype=linux_secure ("Failed password" OR "invalid user")
| rex "invalid user (?<target_user>\\w+)"
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip target_user
| convert ctime(first_seen)
| convert ctime(last_seen)
| sort - count
