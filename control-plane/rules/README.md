# DeepWire DPI — Rules Directory

This directory holds the configuration files and databases used by the Go Control Plane.

## Required Files

### `GeoLite2-Country.mmdb`

The MaxMind GeoLite2 Country database is **required** for Geo-IP firewalling.

**Download instructions:**

1. Create a free account at [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup).
2. Navigate to **My Account → GeoIP2 / GeoLite2 → Download Databases**.
3. Download **GeoLite2 Country** in the **MaxMind DB** (`.mmdb`) format.
4. Place the `GeoLite2-Country.mmdb` file in this directory.

> ⚠️ Do **not** commit the `.mmdb` file to version control — it is covered by the MaxMind EULA and is already listed in `.gitignore`.

### `blocklist.txt`

A plain-text list of blocked SNI domains, one per line. Lines starting with `#` are treated as comments.
