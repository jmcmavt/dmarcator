# dmarcator

Generate DNS records that lock down a parked (non-sending) domain so it can't be used for spoofing or phishing.

For each domain, dmarcator produces:

| Record | Purpose |
|--------|---------|
| **Null MX** (`0 .`) | The domain accepts no mail ([RFC 7505](https://www.rfc-editor.org/rfc/rfc7505)) |
| **SPF** (`v=spf1 -all`) | No server may send for the domain. A wildcard `*` record covers subdomains, since SPF isn't inherited |
| **DMARC** (`p=reject; sp=reject`) | Receivers reject anything that fails, including mail from subdomains |

If you set a report mailbox (`--rua`) on a different domain, it also generates the `_report._dmarc` authorization record that domain needs in order to receive your reports.

> **Only use this on domains that send no email.** Publishing these records on a domain that sends mail will make that mail fail.

A free tool by [joseph mcmahon](https://joemac.io).

## Two ways to use it

- **Web page:** open `dmarcator.html` in a browser, or host it anywhere static. It runs entirely client-side. Nothing you enter is sent anywhere.
- **Command line:** `dmarcator.py` needs Python 3.10+ and has no dependencies.

Both produce identical output.

## Command-line usage

```
python dmarcator.py                         # prompts for domains
python dmarcator.py mycompany.net
python dmarcator.py a.net b.com --rua dmarc-reports@yourmaindomain.com
python dmarcator.py -f domains.txt
python dmarcator.py -f domains.txt --format csv -o records.csv
python dmarcator.py mycompany.net --zone -o mycompany.net.zone
```

### Options

| Option | Description |
|--------|-------------|
| `domains` | One or more domains. If none are given (and no `-f`), you're prompted |
| `-f`, `--file FILE` | Read domains from a plain `.txt` file. Can be combined with domains on the command line |
| `--rua ADDRESS` | Mailbox for DMARC aggregate reports (optional) |
| `--format FMT` | `zone` (default), `table` or `csv` |
| `--no-wildcard` | Skip the wildcard SPF record for subdomains |
| `--zone` | Include placeholder SOA/NS records (zone format only) |
| `-o`, `--output FILE` | Write to a file instead of the screen |
| `-h`, `--help` | Show help |

The intro text goes to stderr, so redirected output and `-o` files stay clean.

### Domain list files

One domain per line. Blank lines and `#` comments are ignored. Commas and spaces between domains also work.

```
# parked brand names
mycompany.net
mycompany.org, mycompany.io   # old product
```

Input is cleaned up automatically: `https://Example.com/path` becomes `example.com`, and internationalized names are converted to punycode. Duplicates are removed, and invalid entries are reported and skipped without stopping the rest.

## Output formats

**`zone`** is a BIND-style zone fragment, with comments, for each domain. `--zone` adds placeholder SOA/NS records (replace these with your provider's values).

**`table`** and **`csv`** are flat rows with the columns `zone, name, type, value, ttl`. TXT values are unquoted, which is what most DNS provider UIs expect. Use these for Cloudflare, Route 53, GoDaddy, Microsoft 365 and similar.

```
ZONE       NAME                  TYPE  VALUE                                                  TTL
---------  --------------------  ----  -----------------------------------------------------  ----
a.net      @                     MX    0 .                                                    3600
a.net      @                     TXT   v=spf1 -all                                            3600
a.net      *                     TXT   v=spf1 -all                                            3600
a.net      _dmarc                TXT   v=DMARC1; p=reject; sp=reject; rua=mailto:r@other.com  3600
other.com  a.net._report._dmarc  TXT   v=DMARC1                                               3600
```

The last row belongs in the zone for the report-receiving domain (`other.com`), not the parked domain. Its `zone` column shows which is which.

## Notes

- dmarcator only generates records. It doesn't check what's already published or change any DNS. Check the domain doesn't send mail before you publish.
- DMARC reports are optional. Without `--rua`, the policy still applies, but you won't receive reports.
- A wildcard `*._report._dmarc` TXT record (`v=DMARC1`) in the report domain's zone can replace the per-domain authorization records if you manage many domains.

## License

[MIT](LICENSE) © 2026 Joseph McMahon
