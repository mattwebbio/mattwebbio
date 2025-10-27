---
layout: post
title: "Installing HP M254DW firmware 20200612 on macOS: last version before toner DRM"
date: 2025-10-27
excerpt: "How to install firmware 20200612 on your HP Color LaserJet Pro M254DW with macOS - the last version before HP's cartridge DRM - so you can use $50 third-party toners instead of $400+ OEM cartridges."
has_ai: true
comments: true
---

**TL;DR**: HP implemented cartridge DRM in October 2020. Firmware 20200612 is the last version before that. You can install it using `lpr` to send the firmware file from the Internet Archive directly to the printer. [Jump to the firmware download](#finding-the-firmware) or [the macOS installation steps](#the-installation-process) if you already know why you're here. Or the [quick reference](#quick-reference) with just the commands.

---

I found an HP Color LaserJet Pro M254DW on Facebook Marketplace for $50. Plugged it in, printed a config page, and found it was running firmware version 20171210 from December 2017.

Good news: that's from before HP implemented their cartridge DRM. Better news: I could upgrade to firmware 20200612 - the last pre-DRM version from June 2020 - and get three years worth of bug fixes and improvements while keeping compatibility with third-party toners.

Here's the math that makes this worthwhile: A set of four OEM HP toner cartridges costs almost $400 ([$285 for color](https://www.amazon.com/HP-CF501A-CF502A-Cartridges-Magenta/dp/B07TK514MK/) and [$89 for black](https://www.amazon.com/HP-CF500A-Original-Cartridge-LaserJet/dp/B074KTXVYP/) ***regular*** yield cartridges as of writing). Third-party toners? A little over $50 for the same set ([$57 for True Image black ***and*** color](https://www.amazon.com/dp/B07MCBRXP8) ***high*** yield cartridges as of writing). The printer was $50. Even if I only print a few thousand pages over the printer's lifetime, I'm saving hundreds of dollars.

New color lasers are expensive - often over $500, and they all come with DRM that locks you into expensive consumables. The older models without DRM are a bargain by comparison, and a printer that has worked perfectly for several years is likely to have plenty of life left. As a result, buying a working M254DW for $50 rather than Wirecutter's top pick just seemed sensible.

Your situation might be different. Maybe your printer already has DRM firmware and you need to downgrade. Maybe it shipped with firmware from 2019 and you could go either direction. Doesn't matter - the target is the same: firmware 20200612, the sweet spot where you get modern-ish stability without HP's cartridge lockout.

## The DRM Problem

In October 2020, HP pushed a firmware update they call "Dynamic Security," which is marketing speak for "DRM that blocks your cheap toner." If your printer has this firmware, it will reject non-HP cartridges with a cheerful error message about how you need "genuine HP supplies" for "the best printing experience." Translation: pay us over $400 per cartridge set or your printer becomes a paperweight.

HP's system works by checking the cryptographic chip on each toner cartridge. Genuine HP cartridges have keys that the printer validates. Third-party cartridges don't have these keys, so the printer refuses to print. This isn't a safety issue or a quality issue - third-party toner works fine mechanically. It's purely a business decision to lock you into HP's ecosystem.

And HP is aggressive about it. If you have automatic updates enabled, the printer will download and install DRM firmware on its own. Once that happens, your third-party cartridges stop working immediately. No warning, no grace period.

The good news: firmware changes still work on the M254DW. The M254DW doesn't appear to have anti-rollback protection based on community testing. We can install firmware 20200612 and disable automatic updates to prevent HP from forcing the DRM version back onto the printer.

The bad news: HP has removed old firmware files from their official download servers. They know exactly what we're doing and they'd prefer we didn't. But the Internet Archive has our back.

## Finding the Firmware

The firmware version we need is `20200612` - released June 12, 2020, four months before HP implemented Dynamic Security. Community testing over the past 4+ years has confirmed that 20200612 is the last version without Dynamic Security checks.

HP used to host this at their FTP server. If you try to download it now, you'll get a 404. HP has memory-holed it. Fortunately, the Internet Archive's Wayback Machine captured it before HP could scrub it from existence.

Here's the Wayback Machine link (click to download): [HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu](https://web.archive.org/web/20201110192924/http://ftp.hp.com/pub/networking/software/pfirmware/HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu)

Or if you prefer to copy-paste the URL:
```
https://web.archive.org/web/20201110192924/http://ftp.hp.com/pub/networking/software/pfirmware/HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu
```

Download this file. It's about 33.6MB. The Wayback Machine serves archived content exactly as it was originally captured - this firmware file is unchanged from HP's original distribution.

After downloading, verify the file integrity:

```bash
# Check file size (should be around 33.6MB)
ls -lh HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu

# Verify SHA-256 hash
shasum -a 256 HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu
```

The expected SHA-256 hash is:
```
91c7f51ceba2386f3b94dcb9da20c669ab10b1ee3a9b1e1f742c40091920188e
```

If your hash matches, you're good to go. If it doesn't match, re-download the file - something got corrupted in transit.

## The Installation Process

Windows has an HP firmware updater GUI, but macOS doesn't. On Mac, the command-line method using `lpr` is the only way I could find to update the printer firmware to a specific version. This actually makes the process more straightforward: you send the firmware file to the printer like it's a print job, and the printer handles the rest.

### Step 1: Enable firmware downgrades (or upgrades) on the printer

Before you can switch firmware versions, you need to enable it in the printer's settings.

From the printer's control panel:
1. Navigate to **Setup** (the gear ⚙️ icon) -> **Service** -> **LaserJet Update** -> **Manage Updates**
1. If you're ***downgrading*** from a ***newer version***, select **Allow Downgrade**, choose **Yes**
1. If you're ***upgrading*** from an ***older version***, select **Allow Updates**, choose **Yes**

This tells the printer to accept the firmware version we're about to send it. Without this setting enabled, the printer will reject the firmware.

### Step 2: Find your printer name

Open Terminal and run:

```bash
lpstat -p -d
```

This lists all printers configured on your system. You'll see output like:

```
printer HP_Color_LaserJet_M254DW_0 is idle.  enabled since Mon Oct 27 14:32:15 2025
```

Note the printer name - in this example, it's `HP_Color_LaserJet_M254DW_0`. Your printer name might be slightly different depending on how macOS named it when you added it.

### Step 3: Send the firmware file

Navigate to wherever you downloaded the firmware file, then run:

```bash
lpr -P HP_Color_LaserJet_M254DW_0 ./HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu
```

Replace `HP_Color_LaserJet_M254DW_0` with your actual printer name from step 2, and adjust the path to wherever you saved the firmware file.

The `lpr` command sends the firmware file to the printer as if it were a print job. The printer recognizes it as a firmware update file and processes it accordingly.

### Step 4: Wait for the update

The printer will start processing the firmware update immediately. You'll see the control panel display change to show update progress. This takes 5-10 minutes:

1. The printer receives and validates the firmware file
2. It flashes the new firmware to memory (3-5 minutes with a progress bar)
3. It reboots (2 minutes)

Don't turn off the printer. Don't unplug it. Don't send it any print jobs. Just let it complete the process.

### Step 5: Verify the firmware version

Once the printer reboots, print a configuration page from the control panel. Look for the firmware version. It should show `20200612` or similar (the exact format varies, but you'll see the date code).

## Locking It Down

You've successfully installed firmware 20200612. Now HP is going to try to "help" you by automatically updating it to the DRM version. We need to prevent this.

### Disable automatic firmware updates

From the printer's control panel:
1. Navigate to **Setup** (the gear ⚙️ icon) -> **Service** -> **LaserJet Update** -> **Manage Updates**
1. Select **Allow Updates**, choose **No**
1. Select **Check Automatically**, choose **Off**
1. Select **Prompt Before Install**, choose **Always Prompt**

That's it. The printer won't check for or install firmware updates unless you explicitly tell it to.

## Long-Term Maintenance

Once you've installed firmware 20200612 and disabled automatic updates, the printer should stay on this version indefinitely. If you ever need to factory reset the printer, remember to disable automatic updates again - a reset might re-enable them.

## Cost-Benefit Analysis

Let's do the math on why this used printer approach makes sense:

**Used M254DW with third-party toner (5-year timeline):**
- Used printer: $50
- Third-party toner (2-3 sets over 5 years): $80-120
- **Total: ~$170**

**New color laser with DRM:**
- New printer with built-in DRM: $350-$1,000
- Locked into OEM toner: $350+ per set
- Same 2-3 sets over 5 years: $700-$1,050
- **Total: $1,050-$2,050**

**Why the used M254DW is so cheap:**
The M254DW hasn't been manufactured in years. Most used models on the market already have DRM firmware installed, which makes them nearly worthless - who wants to pay $50 for a printer that forces you to buy $400 toner sets? Finding one with pre-DRM is so easy (at least in my area), so it's truly an exceptional deal. I found mine on Facebook Marketplace on a Sunday evening and picked it up in 1 hour.

**The real savings:**
Third-party toner at $50/set versus $400+ for OEM is where the money adds up. Over the printer's lifetime, you're saving $700-$1,000 on consumables alone. And you avoided spending $800-1,500 on a new printer that would lock you into the same expensive ecosystem.

## Why This Matters

Sometimes the best printer is a used one from years ago. Secondhand equipment is fine - and for a printer is a _screaming_ deal by comparison. Why would you pay $500+ for a ***nice*** new printer when a ***great*** used one works perfectly and costs a tenth as much? A printer that has worked perfectly for several years is likely to have plenty of life left.

The firmware downgrade is just pragmatism. HP's DRM doesn't make the printer work better or improve print quality. Third-party toners works fine mechanically. The DRM exists solely to lock you into expensive consumables. Installing firmware 20200612 removes that lock. Simple as that.

This is a good deal because it's cheap and it works. That's all the justification you need.

## Final Thoughts

I've been running my M254DW on firmware 20200612 since I bought it. Third-party toners works perfectly. Print quality is identical (as far as I can tell) to OEM cartridges. I've saved hundreds of dollars, and I'm not locked into HP's ecosystem.

The printer itself is an unbeatable value at this price point. If you can find one locally for $50-$100, it's worth grabbing. Just remember to install firmware 20200612 and disable automatic updates to avoid HP's cartridge DRM.

---

## Quick Reference

If you just want the commands:

```bash
# Download firmware from the Wayback Machine:
# https://web.archive.org/web/20201110192924/http://ftp.hp.com/pub/networking/software/pfirmware/HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu

# Verify hash (expected: 91c7f51ceba2386f3b94dcb9da20c669ab10b1ee3a9b1e1f742c40091920188e)
shasum -a 256 HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu

# Enable downgrade on printer: Setup -> Service -> LaserJet Update -> Manage Updates
# _or_ enable updates if upgrading from older version: Setup -> Service -> LaserJet Update -> Manage Updates

# Find printer name
lpstat -p -d

# Send firmware to printer (replace printer name as needed)
lpr -P HP_Color_LaserJet_M254DW_0 HP_Color_LaserJet_Pro_M254_dw_Printer_series_20200612.rfu

# Wait 5-10 minutes for update to complete
# Then disable automatic updates: Setup -> Service -> LaserJet Update -> Manage Updates
```
