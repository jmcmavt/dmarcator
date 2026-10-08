#!/usr/bin/env python3
"""
dmarcator.py is a free tool offered by joseph mcmahon. https://joemac.io

Generate DNS records that lock down a parked (non-sending) domain:

  * Null MX   - domain accepts no mail (RFC 7505)
  * SPF       - no server may send for the domain (-all)
  * DMARC     - reject anything that fails (p=reject, sp=reject)

Usage:
  python dmarcator.py                       # prompts for the domain
  python dmarcator.py mycompany.net
  python dmarcator.py a.net b.com --rua dmarc-reports@yourmaindomain.com
  python dmarcator.py -f domains.txt
  python dmarcator.py mycompany.net --zone -o mycompany.net.zone
"""

print("dmarcator.py is a free tool offered by joseph mcmahon, 2026. https://joemac.io")

import argparse
import csv
import io
import re
import sys

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")


def normalize_domain(raw: str) -> str:
    """Clean up user input and validate it as a domain name."""
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)   # strip http:// etc.
    d = d.split("/")[0].rstrip(".")    # strip paths and trailing dot
    if not d:
        raise ValueError("empty domain")

    try:  # support internationalized names by converting to punycode
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"'{raw}' is not a valid domain name")

    labels = d.split(".")
    if len(labels) < 2 or len(d) > 253 or not all(LABEL_RE.match(l) for l in labels):
        raise ValueError(f"'{raw}' is not a valid domain name")
    return d


def validate_rua(rua: str) -> tuple[str, str]:
    """Return (address, domain_of_address)."""
    rua = rua.strip().removeprefix("mailto:")
    m = EMAIL_RE.match(rua)
    if not m:
        raise ValueError(f"'{rua}' is not a valid email address")
    return rua, normalize_domain(m.group(1))


def is_same_org(domain: str, report_domain: str) -> bool:
    """True if the report address is on the domain itself or one of its subdomains."""
    return report_domain == domain or report_domain.endswith("." + domain)


def build_records(domain: str, rua: str | None, wildcard_spf: bool):
    """Return (records, authorization_record_or_None).

    records: list of (name, type, value) for the parked domain's zone.
    authorization: (name, type, value, zone) for the reporting domain's zone.
    """
    records = [
        ("@", "MX", "0 ."),
        ("@", "TXT", '"v=spf1 -all"'),
    ]
    if wildcard_spf:
        records.append(("*", "TXT", '"v=spf1 -all"'))

    dmarc = "v=DMARC1; p=reject; sp=reject"
    authorization = None
    if rua:
        address, report_domain = validate_rua(rua)
        dmarc += f"; rua=mailto:{address}"
        if not is_same_org(domain, report_domain):
            authorization = (
                f"{domain}._report._dmarc",
                "TXT",
                '"v=DMARC1"',
                report_domain,
            )
    records.append(("_dmarc", "TXT", f'"{dmarc}"'))
    return records, authorization


def render(domain, records, authorization, include_zone_header, serial):
    out = []
    out.append(f"; ===== Parked domain: {domain} =====")
    out.append(f"$ORIGIN {domain}.")
    out.append("$TTL 3600")
    out.append("")

    if include_zone_header:
        out += [
            "; --- Zone authority (PLACEHOLDERS: replace with your provider's values) ---",
            f"@       IN  SOA   ns1.example-dns.com. hostmaster.{domain}. (",
            f"                  {serial:<11} ; serial (YYYYMMDDNN)",
            "                  7200        ; refresh",
            "                  3600        ; retry",
            "                  1209600     ; expire",
            "                  3600 )      ; negative-caching TTL",
            "",
            "@       IN  NS    ns1.example-dns.com.",
            "@       IN  NS    ns2.example-dns.com.",
            "",
        ]

    comments = {
        ("@", "MX"): "; Null MX: domain accepts no mail (RFC 7505)",
        ("@", "TXT"): "; SPF: no server may send for this domain",
        ("*", "TXT"): "; SPF for subdomains (SPF is not inherited)",
        ("_dmarc", "TXT"): "; DMARC: reject failures, including subdomains",
    }
    for name, rtype, value in records:
        out.append(comments[(name, rtype)])
        out.append(f"{name:<7} IN  {rtype:<4} {value}")
        out.append("")

    if authorization:
        name, rtype, value, zone = authorization
        out.append(f"; ----- Add this to the zone for {zone} (the REPORT-RECEIVING domain) -----")
        out.append(f"; Authorizes {zone} to receive DMARC reports about {domain}.")
        out.append(f"; (Or publish one wildcard instead:  *._report._dmarc  IN  TXT  {value})")
        out.append(f"{name}.{zone}.  IN  {rtype}  {value}")
        out.append("")
    return "\n".join(out)


ROW_COLS = ["zone", "name", "type", "value", "ttl"]


def flat_rows(domain, records, authorization):
    """Flat rows for table/CSV output. Values are unquoted, as most DNS UIs expect."""
    rows = [dict(zip(ROW_COLS, (domain, n, t, v.strip('"'), 3600))) for n, t, v in records]
    if authorization:
        name, rtype, value, zone = authorization
        rows.append(dict(zip(ROW_COLS, (zone, name, rtype, value.strip('"'), 3600))))
    return rows


def render_table(rows):
    widths = [max(len(c), *(len(str(r[c])) for r in rows)) for c in ROW_COLS]
    line = lambda r: "  ".join(f"{r[c]!s:<{w}}" for c, w in zip(ROW_COLS, widths)).rstrip()
    head = {c: c.upper() for c in ROW_COLS}
    rule = "  ".join("-" * w for w in widths)
    return "\n".join([line(head), rule, *map(line, rows)])


def render_csv(rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ROW_COLS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().rstrip("\n")


def read_domain_file(path: str) -> list[str]:
    """Read domains from a text file: one per line, blank lines and # comments ignored."""
    domains = []
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.split("#", 1)[0]
            domains += [d for d in re.split(r"[,\s]+", line.strip()) if d]
    return domains


INTRO = """\
What this tool does
  Generates DNS records that lock down a parked (non-sending) domain so it
  can't be used for spoofing or phishing:
    - Null MX : the domain accepts no mail (RFC 7505)
    - SPF     : no server may send for the domain (v=spf1 -all)
    - DMARC   : reject anything that fails (p=reject, sp=reject)

Options
  domains         one or more domains (you'll be prompted if none are given)
  -f, --file F    read domains from a plain .txt file, one per line (blank
                  lines and # comments are ignored); can be combined with
                  domains given on the command line
  --rua ADDRESS   mailbox for DMARC aggregate reports (optional). If it's on a
                  different domain, an authorization record for that domain's
                  zone is also generated.
  --no-wildcard   skip the wildcard SPF record (*) covering subdomains
  --format FMT    zone (default, BIND zone file), table (for copying into a
                  DNS provider's UI) or csv
  --zone          include placeholder SOA/NS records (zone format only)
  -o, --output F  write the records to file F instead of the screen
  -h, --help      show the full help text

Examples
  python dmarcator.py mycompany.net
  python dmarcator.py a.net b.com --rua dmarc-reports@yourmaindomain.com
  python dmarcator.py -f domains.txt
  python dmarcator.py -f domains.txt --format csv -o records.csv
  python dmarcator.py mycompany.net --zone -o mycompany.net.zone
"""


def main():
    # Intro goes to stderr so redirected/-o output stays clean.
    print(INTRO, file=sys.stderr)
    p = argparse.ArgumentParser(description="Generate parked-domain SPF/DMARC/null-MX records.")
    p.add_argument("domains", nargs="*", help="one or more domains (prompts if omitted)")
    p.add_argument("-f", "--file", metavar="FILE",
                   help="plain .txt file of domains, one per line (# comments allowed)")
    p.add_argument("--rua", help="mailbox for DMARC aggregate reports (optional)")
    p.add_argument("--no-wildcard", action="store_true",
                   help="skip the wildcard SPF record for subdomains")
    p.add_argument("--zone", action="store_true",
                   help="include placeholder SOA/NS records (zone format only)")
    p.add_argument("--format", choices=["zone", "table", "csv"], default="zone",
                   help="output format (default: zone, a BIND zone file)")
    p.add_argument("-o", "--output", help="write to this file instead of stdout")
    args = p.parse_args()

    raw_domains = list(args.domains)
    if args.file:
        try:
            raw_domains += read_domain_file(args.file)
        except OSError as e:
            sys.exit(f"Error: can't read {args.file}: {e.strerror or e}")
    if not raw_domains:
        entered = input("Enter domain(s), separated by spaces or commas: ")
        raw_domains = re.split(r"[,\s]+", entered.strip())
        raw_domains = [d for d in raw_domains if d]
    if not raw_domains:
        sys.exit("No domain provided.")

    from datetime import date
    serial = int(date.today().strftime("%Y%m%d") + "01")

    chunks, rows, errors, seen = [], [], [], set()
    for raw in raw_domains:
        try:
            domain = normalize_domain(raw)
            if domain in seen:
                continue
            records, auth = build_records(domain, args.rua, not args.no_wildcard)
            seen.add(domain)
            if args.format == "zone":
                chunks.append(render(domain, records, auth, args.zone, serial))
            else:
                rows += flat_rows(domain, records, auth)
        except ValueError as e:
            errors.append(str(e))

    for e in errors:
        print(f"Error: {e}", file=sys.stderr)
    if not seen:
        sys.exit(1)

    if args.format == "zone":
        result = "\n".join(chunks)
    elif args.format == "csv":
        result = render_csv(rows)
    else:
        result = render_table(rows)
    if args.output:
        with open(args.output, "w") as f:
            f.write(result + "\n")
        print(f"Wrote {len(seen)} domain(s) to {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
