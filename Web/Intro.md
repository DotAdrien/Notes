# 🚲 Web exploitation

This documents is for Web explotation

---

## 🦊 FireFox

- View all source code of page easy\
  Type `view-source:` before url

---


HTTP Basic Authentication is defined in RFC 7617, which specifies that the credentials (username and password) should be transported as a base64-encoded string within the HTTP Authorization header. This method is straightforward but not secure over non-HTTPS connections, as base64 is not an encryption method and can be easily decoded. The real threat often comes from weak credentials that can be brute-forced.
