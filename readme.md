## CVSS implementation in TypeScript

 It is based off the reference implementation at [https://github.com/RedHatProductSecurity/cvss-v4-calculator](cvss-v4-calculator)

Supported versions
- [ ] CVSS20
- [ ] CVSS30
- [ ] CVSS31
- [x] CVSS40

### Basic CVSS anatomy

```
                       Availability Impact ╮
                      Integrity Impact ╮   │
            Confidentiality Impact ╮   │   │
                 Scope Changed ╮   │   │   │
                             ╭─┴╮╭─┴╮╭─┴╮╭─┴╮
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N
╰┬─────╯╰┬──╯╰┬──╯╰┬──╯╰┬──╯
 │       │    │    │    ╰ User Interaction is None
 │       │    │    ╰ Privileges Required is None
 │       │    ╰ Attack Complexity is Low
 │       ╰ Attack Vector is Network
 ╰ This is a CVSS 3.1

```
