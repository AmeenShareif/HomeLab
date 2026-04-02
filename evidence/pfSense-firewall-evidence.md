# pfSense Firewall Evidence

Date: Mar 29 2026

These were the pfSense pages I used to set the lab block rule.

## Firewall Rule Form

The rule edit page was open on the LAN interface.

- Action was set to `block`
- Source was left as `any`
- Destination was left as `any`
- The description field was available for the rule name
- The page warns that `block` drops traffic silently

## Current LAN Rules

The LAN rules page showed:

- `lab-scan-block`
- `Default allow LAN to any rule`
- `Default allow LAN IPv6 to any rule`

The list also showed the LAN tab selected and the rules ordered on the page.

## Save Response

When I saved the rule, pfSense showed:

- `The firewall rule configuration has been changed.`
- `The changes must be applied for them to take effect.`

That tells me the rule edit was saved but not active yet.

## Apply Response

After I clicked apply, pfSense showed:

- `The changes have been applied successfully.`
- `The firewall rules are now reloading in the background.`

This is the part that matters because it confirms the rule was actually pushed into the live firewall config.

## Notes

The HTML captures stay in the repo history. This Markdown note is the version I want in the repo.
