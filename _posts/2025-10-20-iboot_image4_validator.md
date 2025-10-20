---
layout: post
title:  "An analysis of iBoot's Image4 parser"
date:   2025-10-20 01:00:03 -0400
---

# An analysis of iBoot's Image4 parser

A note: while this blog post is being published in 2025, this research was initially started in 2024, and has slowly evolved over time. This blog post documents my discoveries about the iBoot Image4 parser and the security implications I noted of design decisions made. (Since Image4 is used in other places, these implications actually extend beyond iBoot and into the SEP, the kernel, and other places as well)

This post also presumes you're familiar with how PKI works and how digital signatures work. This post is also fairly dense, as I wanted to prioritize the correctness of information in this post to do a proper analysis, so I've split the post into multiple parts and sections, as well as provided a table of contents so if you want to read up to a certain point and pick it back up, you can do that. I should also disclaim ahead of time that while this post is deep, it is not *comprehensive*, I cannot possibly cover every minute detail because that post would be very very long and not easy to read even for as verbose as this post is.



## Table of contents

1. [Prelude](#prelude-a-hopefully-quick-briefer-on-iboot-and-its-position-in-idevice-security)
2. [Threat model](#whats-our-threat-model)
3. [Part 0: Image4 format](#part-0-the-image4-format)
    - [How does Apple parse Image4 files?](#how-does-apple-parse-image4-files)
4. [How iBoot parses an Image4, from start to finish](#how-iboot-parses-an-image4-from-start-to-finish)
    - [Part 1: knowing the environment](#part-1-knowing-the-environment)
    - [Part 2: initial parsing](#part-2-initial-parsing) 
    - [Part 3: trust evaluation](#part-3-trust-evaluation)
    - [The property validation callback](#the-property-validation-callback)
    - [Part 4: cleanup and final steps](#part-4-cleanup-and-final-steps)
5. [How secure is iBoot's Image4 parser?](#how-secure-is-iboots-image4-parser)
6. [A discussion on Image4 patches](#a-discussion-on-image4-patches)
   - [Scenario 1: someone who wants to use a custom TSS server to sign their own manifests and use their own certificates without patching Image4 validation routines](#scenario-1-someone-who-wants-to-use-a-custom-tss-server-to-sign-their-own-manifests-and-use-their-own-certificates-without-patching-image4-validation-routines) 
   - [Scenario 2: someone who wants to load any Image4 with any arbitrary manifest for any device, with the ability to modify the manifest for their device if needed](#scenario-2-someone-who-wants-to-load-any-image4-with-any-arbitrary-manifest-for-any-device-with-the-ability-to-modify-the-manifest-for-their-device-if-needed)
   - [Mix and match patch](#mix-and-match-patch)


## Prelude: A (hopefully) quick briefer on iBoot and it's position in iDevice security

iBoot is the bootloader used on Apple's ARM platforms. It holds very critical importance in the security model, as many of the security mechanisms on iDevices are actually configured and set up by iBoot (examples of this include CTRR/KIP bounds, PAC key seeds for devices since the A12, and the locations of the Secure Enclave's protected memory regions for its OS, this also applies to devices such as the Vision Pro or Apple silicon Macs.) A compromise in iBoot means that mitigations like CTRR, PAC, MTE (as of the most recent A19 and M5 chips) or TXM can be bypassed, patched, or ignored, and untrusted code can be loaded, which can lead to a malicious or compromised kernel being executed, even the deep sleep handler setup is handled by iBoot so a compromised iBoot could well lead to a more persistent than normal rootkit on iDevices.

iBoot (both as a bootloader in its own right, and in its reduced size ROM form as the bootrom/"SecureROM" of all iDevices since the second gen iPod touch) is also the one responsible for validating every step of the secure boot chain from power-on reset. It ensures that all code in the chain is signed by Apple. To facilitate this, all the raw binary payloads that are part of the secure boot chain (including the kernel) are wrapped in a container format that describes the image as well as holding its signature. On current iDevices (since the iPhone 5S with the A7), this is the Image4 format, and this format and how iBoot parses it will be the central focus of this post. The iBoot images used for analysis in this post will be iBoot-11881.2.10 for the D94AP (iPhone 16 Pro Max), and the 15.3 image for the 14-inch M4 Max MacBook Pro (J614cAP) for any Mac-specific notes. (You can follow along with any iBoot image for the 2024 OS releases for any device, as the Image4 library itself is device-agnostic. (note that some code differences are because of Firebloom checks being injected by the build process or from compiler optimization changes) Some of the symbols used come from either leftover strings in older iBoots inferred to be the same functions by diffing, come from the same version iBoot in RESEARCH_RELEASE style for the D47AP (iPhone 16), or are symbols I defined myself based on what the function does to the system state or reads from the system.

## What's our threat model?

The threat model here is that the attacker is trying to subvert the secure boot chain and load an unsigned or untrusted image via some type of malformed image uploaded either over USB or implanted into local storage, and the attacker potentially has the capability to write arbitrary memory, but does not yet have code execution in iBoot (which is the attacker's end goal here) so they don't have influence on how the parser itself runs.

## Part 0: The Image4 format

The Image4 format is a quite simple format conceptually, as it's fundamentally just an ASN.1 container over a binary payload. For reference, we're going to be looking at an iBoot Image4, SEP firmware Image4, and a kernelcache Image4 from an M4 Mac mini in reduced security mode in [Lapo Luchini's online ASN.1 parser](https://lapo.it/asn1js/), because OpenSSL is not a fun program to work with and for the purposes of this research, an online ASN.1 decoder and a hex editor are more than enough :)

![iboot image](/assets/images/image4/iboot-image.png)

As we can see, an Image4 contains a magic number ("IMG4") which lets the program validating this file know that it should try to use Image4 semantics to validate it, as well a couple of SEQUENCE sections. The first one after the magic being a SEQUENCE which has magic "IM4P" as an IA5String. This is an Image4 payload, it's pretty simple conceptually, the other IA5Strings are the tag of the image (we'll see how this is used later) and the version string. The octet string here is the actual binary payload, and the perceptive among you might notice the first 4 bytes in that octet string are the string 'bvx2' which implies a compressed payload, and the sequence after the octet string in the above image describes the uncompressed size. (compression is optional, the payload can be uncompressed and used raw, as-is, in which case the binary payload octet string is the end of the payload, most Apple payloads are compressed as of iOS 15 or so)

One note is that for encrypted images, as seen below, there are also sections below the binary payload octet string that describe the keybags (which are themselves encrypted with either the AP or Secure Enclave's GID key, depending on whether it's the SEP firmware/stage 1 patches) and the encryption schema used on the image (supported encryption schemes are AES 128, 192, or 256, with 256 being the only value actively used in production payloads.) (encryption is optional, like compression)

Note that since iOS 15, the payload section can canonically contain a section called the "payload properties" section (magic 'PAYP'), this is used in payloads like the kernelcache or the SEP firmware to define additional properties that aren't part of the manifest spec that need to be defined on a per payload basis such as kernel RX/RO regions for SPTM (the payload properties *are* authenticated by the manifest by virtue of the payload properties digest value.) In the past, some of these payload properties were stored in an ASN.1 encoded sequence with magic 'IMPL' and shoved into the version string in the IM4P header.
![kernel with payload properties](/assets/images/image4/kernel-payload-properties.png)
![sep image](/assets/images/image4/sep-image.png)

The next big sequence has magic "IM4M", this is the manifest, which holds properties for both images it is set to validate against ("object properties" as Apple calls them), and the device or OS itself that the manifest is constrained against ("manifest properties"). This is the only actual "signed" part, as for efficiency and historical reasons (the manifest itself has roots in the older "APTicket" signing scheme used later on for Image3 devices) Apple signs a single binary blob with all the hashes of the bootchain components the manifest evaluates against included (such as boot images, kernelcache, signed system volume root hash as of iOS 15, etc.) This lets Apple speed up image validations as if the manifest being used matches what was used to validate previous bootchain components (this will be explained more later, as it's necessary to understand how Mac secure boot works), all that needs to happen is a simple hash check on the image itself against the digest and it's own properties, instead of having to revalidate the hardware environment against the global manifest properties that apply to all images.

![object properties](/assets/images/image4/object-properties.png)

One note is that Apple in their firmware restore images actually doesn't ship full Image4 files, since unlike Image3 (which started out as having pre-signed firmware payloads before transitioning to requiring personalization on production devices, in addition to the bootrom intentionally not recognizing APTicket formats for pre-A7 devices), every Image4 file is expected to have a manifest signed by Apple describing the properties of the manifest stitched separately to the raw Image4 payload itself. Since all parts of the bootchain have transitioned to Image4, Apple can now insist on shipping the payloads separately and having the manifest that describes all components signed separately. (This is almost always done by what Apple calls the "Tatsu" server, henceforth referred to in this post as TSS) This is important in Apple's model, because it means they are foundationally in control of what versions of iOS are authorized to be installed for a particular device. (most recently with the launch of iOS and iPadOS 26, Apple recently stopped authorizing installations of iOS 18 for devices that support iOS 26, so attempts to restore those versions will fail.)

There is another section of Image4 files that is important later on and is dynamically generated by the restore client (MobileDevice/idevicerestore/etc) called restore info (magic "IM4R"), and it's role is to store a couple of things, all used by boots that come from either SEPROM or SecureROM, namely the raw boot nonce (the manifest contains the boot nonce hash) which is required for local booting, and on newer devices, the ucon/ucer properties that LLB and iBSS require (this is for some TBM that the AP seems to implement on the A16 and newer. Also seems to be in some SEP Image4s?) We'll only be discussing the boot nonce here, but restore info is not just for the boot nonce anymore.

One note that should be mentioned here: an Image4 file is not required to have all of the sections present, and in fact it's very common to see one with only one or two of them. To note the prominent examples of this: Local policies for Mac secure boot and Cryptexes on all devices are basically Image4s that only practically have the manifest section and a unique set of manifest tags that are parsed by iBoot just for local policies. (A separate callback is used to authenticate local policies) Most Image4s signed by the TSS server do not have the restore info section, having only payload and manifest, as restore info only really used for images that are booted by SecureROM or SEPROM. It's even possible to have an Image4 that's purely a payload and nothing else. (although this isn't necessarily a practical use case as we'll see later)

### How does Apple parse Image4 files?

Apple implements Image4 validation slightly differently in each of their boot components that implement Image4 validation (iBoot, SEPROM, AppleImage4 kext, etc), and differing amounts of input validation are done in these implementations based on the requirements. However, all of them fundamentally wrap around a shared library that all of them include, called `libImg4Decode` by Apple. This shared library is what actually does all of the parsing of the Image4 binary payload itself. 

Of note is that libImg4Decode is built on top of two other libraries that Apple's maintained for a long time now, namely corecrypto (which is made source-available by Apple at [this link](https://developer.apple.com/security), currently it hosts the macOS Sequoia/iOS 18 revisions, but will hopefully be updated to the Tahoe/iOS 26 versions soon) for the cryptographic primitives such as SHA, RSA, ECDSA, etc, and libDER (which was open source for many many versions, but is no longer disclosed by Apple, I suspect for multiple reasons) libImg4Decode itself and by consequence corecrypto and libDER is shipped with it's symbol names as part of the AppleImage4 kext that Apple ships as part of the Kernel Debug Kit, the version being used as reference here is the one from the macOS Tahoe build 25A353 KDK, the one for the Tahoe release candidate.

The validating program (in this post's case, iBoot) takes the ASN.1 wrapped Image4 payload, manifest, and restore info and instantiates a context structure describing parts (the size of this structure has been 0x1C8 bytes for a while, even with additions in recent devices of certain properties, the below excerpt describing this context structure along with other info is taken from [this PongoOS header](https://github.com/checkra1n/PongoOS/blob/iOS15/src/lib/img4/img4.h), comments are mine and note that this specific context structure is part of libImg4Decode, most known validating programs have program-specific context structures that work as part of their own Image4 validation code)

```c
typedef struct
{
    bool payloadHashValid;
    bool manifestHashValid;
    DERItem payloadRaw;
    DERItem manifestRaw;
    DERItem manb; // "Manifest body" most likely
    DERItem manp; // "Manifest properties"
    DERItem objp; // "Object properties"
    Img4Payload payload;
    Img4Manifest manifest;
    Img4RestoreInfo restoreInfo;
} Img4;

typedef struct
{
    DERItem magic;
    DERItem type;
    DERItem version;
    DERItem payload;
    DERItem keybag; // optional, supports AES 128, 192, or 256 keybags
    DERItem compression; // optional, can be LZSS or LZFSE compression
    uint8_t hash[0x30];  // NOTE: this size of 0x30 is because the largest supported hash size is SHA2-384, older Image4 devices will use SHA1 here.
} Img4Payload;

typedef struct
{
    DERItem magic;
    DERItem zero; //probably a reserved DERItem?
    DERItem properties;
    DERItem signature;
    DERItem certificates; // the cert chain
    DERItem embedded;
    uint8_t full_hash[0x30];
    uint8_t prop_hash[0x30];
} Img4Manifest;

typedef struct
{
    DERItem magic;
    DERItem nonce; //this is NOT just the nonce anymore on newer devices.
} Img4RestoreInfo;
```

One note here is that all of the actual data in memory is pointed to by DERItem structures (This is a common structure used in libDER to represent DER-encoded blobs in memory) (The important ones are represented below, comments again mine)

```c
typedef struct {
	DERByte		*data; //this points to the raw data directly
	DERSize		length; //a size
} DERItem;

//
// DERDecodedInfo is a meta-structure basically encapsulating a DERItem with its ASN.1 tag.
//
typedef struct {
	DERTag		tag;
	DERItem		content;
} DERDecodedInfo;

//
// DERReturn is a standard enum used by both libDER and libImg4Decode functions to indicate success or error conditions.
//
typedef enum {
	DR_Success,
	DR_EndOfSequence,
	DR_UnexpectedTag,
	DR_DecodeError,
	DR_Unimplemented,
	DR_IncompleteSeq,
	DR_ParamErr,
	DR_BufOverflow
} DERReturn;
```

One of the big advantages of how libDER handles DERItems is that this architecture permits libDER to simply just ASN.1 decode any DER-formatted object entirely in place without worrying about copying it in or parsing it to its own structures, meaning that there is less implicit trust required in DER decoding binary blobs in memory. This also means that libDER as-is without Firebloom enhancements has a good degree of resistance to buffer overflow attacks or similar attacks that rely on over or under allocating memory by faking the size. It's also quite a small library, meaning it inherently has lower attack surface as a result of that, and it's very easy to integrate into all stages of boot including the SoC bootroms. (such as AP SecureROM or SEPROM)

The strength of libDER makes libImg4Decode strong by proxy (on top of doing its own checks), and corecrypto itself is also a strong PKI library, being used for multiple years across many Apple projects, so the shared Image4 decoding library should be fairly strong by proxy.

One final note, remember how I said that every section of an Image4 is technically optional and not all have to be included?  As a result of that, nothing in libImg4Decode can assume with certainty any of these sections exist, and so every function that deals with one of these sections must first check for the section's existence before being able to do anything regarding that section, and this is indicated by if `payloadRaw` or `manifestRaw` is not a NULL pointer for those sections, and for restore info, it's checked by seeing if the `nonce` DERItem in it's structure is not NULL (again it's not just for the boot nonce anymore though)

With this context established, we can finally begin examining how iBoot does Image4 parsing in depth. Let's dive in.

## How iBoot parses an Image4, from start to finish

iBoot's Image4 parsing begins when `image_load`, the general function for loading images in iBoot, calls into the function `image4_load_with_payload_properties` to start the process. (this symbol used to be called `image4_load` in older iBoots but got changed in iOS 15 since the concept of payload properties was formalized into the Image4 spec) This function's first argument is a pointer to an iBoot general image context structure, which contains a couple of important pieces of info. (This image context structure has existed almost since the Image3 format was introduced for 32-bit devices, so a good chunk of this structure is applicable to Image3 devices too.)

```c
struct iboot_image_info {
    char iboot_image_source_tag[4]; // either 'Memz' for images that start in memory, or 'Img4' for images that come from a local source such as the firmware partition (on iDevices) or the NOR (Macs)
    void* image_source; //pointer to where the actual Image4 is in memory (iBoot *never* parses an image directly in place in the case of a local storage image, because that poses a strong risk for time-of-check vs time-of-use attacks)
    uint32_t image_load_flags; // a bit field that encodes certain options that influences how the Image4 parser behaves.
}
```

### Part 1, knowing the environment

The Image4 parser first sets up the stack and zeroes out regions for the Image4 context structure, some device and boot specific properties (such as boot nonce or device ECID and chip ID), and some iBoot specific Image4 context. (This zeroing prevents attacks that rely on placing bad data in there and having it be considered trusted.) Afterwards, it proceeds to read device fuses and GPIO straps to set up the device and boot specific property region (henceforth called the environment properties structure) so that the parser knows what properties are allowed to be in the loaded Image4 manifest and what constraints that manifest must meet, this is how the Image4 parser can tell what manifests are allowed to actually validate an image for a device.

![iboot image4 init](/assets/images/image4/image4-init.png)

Afterwards, it checks the iBoot *general* image context structure, specifically the bit flags field, and it checks bits 2 and 3, with bit 2 representing the image coming from local storage and bit 3 representing whether the Image4 validation should include checking of the nonce hash and writes this to the environment properties structure. (This will be called the "check nonce hash" flag) Now, some of you might be asking why is nonce hash validation seemingly gated behind a flag and not just... always done? That's a great question and one we will circle back to in a bit, because the answer actually has some ramifications on how the trust chain operates overall. Either way, if bit 3 is set, it reads bit 3 of a hardware register (on the T8140/A18 Pro, this register is `0x3082B8028`) and stores the bit value into the environment properties structure (I'll call this flag the "check manifest flag" for reasons you'll see in a bit.)

(heuristically, it seems to be used mostly from the perspective of the AP as a place for iBoot to set some flags it uses based on experimentation with the equivalent register on the A11 - seems to lay in PMGR or miniPMGR space typically so I'll call this register the PMGR flags register) 

Bit 2 of the image load flags is also read and the boolean for whether the parser is booting a locally stored image is stored in the environment properties structure (Henceforth, this flag is being called the "local boot" flag), and then it reads another set of hardware registers (for A18 Pro: `0x300730030-0x30073005C` - size `0x30` bytes) to read off a SHA-384 hash that a previous boot stage stored of the previous manifest. (henceforth called the "previous manifest hash", in the case of SecureROM, this will be 0) Oddly enough, it seems to do this twice, the second time with a different set of registers that are in a different MMIO space, which seems to check what appears to be a lock bit, and panics if it isn't set. (Inspection of multiple SecureROM binaries for the A11 and later devices that have gotten out over time seems to show that it is the one that writes this lock bit and writes a manifest hash to these different registers, maybe this is related to the [Sealed Key Protection](https://support.apple.com/guide/security/sealed-key-protection-skp-secdc7c6c88e/web) feature Apple notes in their [Platform Security guide](https://support.apple.com/guide/security/welcome/web)?)

Finally, if the check nonce hash is set, but the local boot flag is not set (meaning it is not a local boot and the attempted image load is not coming from local storage), it asks the hardware to generate a nonce and later on stores it into another set of hardware registers. (if a nonce has already been generated, it reads that nonce from the hardware registers instead of generating a new one)

![get nonce call](/assets/images/image4/get-nonce-call.png)

![get nonce function](/assets/images/image4/generate-nonce-function.png)

One more note is that on newer devices (A16 and later), it also reads off a series of registers (A18 Pro: `0x3082C8990`, ends at `0x3082C89AC`), (from some reversing it looks like this set of registers is related to the `SIKA` value in the USB serial number string) and writes that to the environment properties.

Okay, that's a *lot* of hardware stuff read to establish the environment, but finally we can move to actually starting parsing.

### Part 2, initial parsing

Finally moving into actual parsing, iBoot starts by loading the Image4 implementation it needs to use for validation. An "implementation" in this case refers to the set of functions that are used to validate an Image4 that is signed and hashed in a particular way, to a particular signing authority (for example, the most common implementation in use on iDevices and Macs today is the RSA4096, SHA384 implementation that chains back to the TSS secure boot root certificate authority)  The implementation, quite literally, defines the root of trust the Image4 validator will compare against. One thing to note is that the implementation is actually part of libImg4Decode and *not* iBoot itself, so the implementation will work the same across all software that implements the same version of the Image4 spec. It also means we have the exact symbol names for the implementation, and so we know what actually goes into an implementation. (chiefly: a function to compute digest, a function to do PKI validation back to the hardcoded root CA for the implementation, a function to verify signature, and OIDs and such.)

![image4 implementation init](/assets/images/image4/init-image4-implementation.png)
![image4 implementation, tatsu rsa4096, sha384 implementation](/assets/images/image4/image4-implementation.png)

Note that failures moving forward in any steps will cause the parser to fail the load of the Image4 and exit, while recording the breadcrumb status somehow of why it failed. (iBoot's breadcrumb space for Image4 specific failures is `0x400400xx`, `xx` being the actual reason for failure, with general image load failures being `0x400300xx`) iBoot proper uses an NVRAM variable for this, `boot-breadcrumbs` in newer versions, while SecureROM will write it to an MMIO register dedicated to storing breadcrumbs.

Next, after calling image4_load_copyobject to copy the image from flash into the destination specified by the caller (which could be the command handler of `go` for example) in the local storage case (and checking if it's actually a valid Image4 object), it checks an odd edge case, specifically bit 8 of the image load flags, if this is set, it takes a fast path out and just leaves the image in the destination, as-is without any processing and returns success. (I'll call this flag the "skip processing" flag) This flag is very rarely used in practice, only being used during SEP firmware loading (because iBoot's job is just to load the firmware to DRAM, it has separate parsing for the SEP firmware's properties which it has to set, SEPROM is what does the validation itself) and (on newer devices) is related to part of ANS2 firmware load. On Image3 devices, this was used to load the APTicket from flash (because the APTicket was parsed separately in dedicated code for it) so really this flag won't ever be set on any scenario that matters to most attackers in our threat model.

Moving forward assuming that flag isn't set, after fixing the object size and checking again, it does its first major call into libImg4Decode, specifically `Img4DecodeInit` (which takes the raw Image4 object in X0, the size in X1 and a pointer to where the Image4 general structure should be created in X2). This creates an instance of the Image4 that the other libImg4Decode functions can use to work with the Image4 itself, and effectively sets it up for validation. It does this by zeroing the struct, then throwing the object through the `DERImg4Decode*` functions (the general one, then `DERImg4Decode{Payload, Manifest, RestoreInfo}` in that order) (which are part of libImg4Decode and not libDER proper) which parses the ASN.1 sequences and DER encoded data of each of those sections' headers, and compares the tags to ensure they are looking at the right Image4 section.

![instantiation](/assets/images/image4/image4-instantiation.png)
![instantiation 2](/assets/images/image4/image4-instantiation-2.png)

Afterwards, the iBoot parser calls `Img4DecodeGetPayloadType` (arguments are img4 context structure in X0 and the pointer to store the type in, in X1) to get the type from the Image4 payload, then optionally sets a callback to capture some properties (I'm not fully sure when or why this is used, but seems to only be really for certain payload types), and then checks the type to see if it's a type that the caller will accept (image_load passes this in as an argument, 0 is a sentinel value that indicates any type is accepted). With this, assuming the type is accepted, initial parsing is done and we can move on to the meat of the post, evaluating whether an Image4 is valid and trusted.

### Part 3, trust evaluation

Trust evaluation (this is Apple's term for validating if an image or payload is validly signed and comes from a trusted authority) starts by checking if the Image4 has a manifest via `Img4DecodeManifestExists` (X0 = Image4 structure, X1 = boolean output pointer to write whether the manifest exists or not). If the manifest doesn't exist, the entire Image4 is treated as if it's untrusted, and this is a really important note to keep in mind, because unlike the Image3 format, there is no concept of an embedded signature to check, if the Image4 doesn't have a valid manifest attached to it, it is not trusted, period. We'll get to how trust evaluation failures are handled in a bit, but keep this in mind.

After validating a manifest exists, if the device doesn't support local policies, (older devices don't, newer iDevices do for Cryptexes and Macs support them for secure boot) the next step is the real trust evaluation, but before that, on those newer devices, Apple stores a boolean (1 for Mac iBoots and Cryptex local policy loads on iOS devices, and 0 otherwise) in the environment properties, and this skips a check later (I'll call this the "local policy backed trust evaluation" flag). 

![local policy backed](/assets/images/image4/local-policy-trust-eval-check.png)

Afterwards, on newer devices, it calls a function called `image4_perform_trust_evaluation_with_callbacks` with one of the arguments being a callback list. (More on this later.) This function is essentially a wrapper to perform trust evaluations from a number of implementations to support less secure scenarios (this is due to how Apple's secure multiboot implementation works on Macs, and this code got ported over to devices that only support Cryptex local policies, albeit with ifdef's that only permit Tatsu-backed authorities to function.)

Alright, now it's time for the real trust evaluation, `Img4DecodePerformTrustEvaluationWithCallbacks` (X0 is the type of the Image4 to evaluate, X1 is the Image4 context structure, X2 is a list of callbacks that need to be run during the trust evaluation, X3 is the Image4 implementation to be used, and X4 is a program specific context structure that the trust evaluation will write into) This function is the one that does the real heavy lifting here.

(Note that for other programs like the SEPROM, it instead calls `Img4DecodePerformTrustEvaluation` which calls the same underlying function but does more sanitization of the arguments to ensure it's in the right format, it's partly a legacy leftover as the trust evaluation arguments used to differ in the past.) 

Just a note, the screenshots for trust evaluation will be from a SecureROM dump I thoroughly analyzed, as trust evaluation can be quite confusing to parse without these comments due to the number of indirect branches, and this code is more or less the same in the D94 RELEASE iBoot I've been following for most of this post. All failures in this function will return `DR_ParamErr` for the return value.

Trust evaluation starts with a lot of sanity checks to ensure that required callbacks and functions in the Image4 implementation are not NULL, and that the manifest is valid. The first step of the trust evaluation after all these checks is to compute the digest of the raw Image4 manifest (all digests are computed by corecrypto's `ccdigest` function), and assuming that goes without a hitch, it will mark in the Image4 context structure the manifest hash as valid.

![trust evaluation sanity checks](/assets/images/image4/trust-eval-sanity-checks.png)

Step 2 is to check if the caller gave in the list of callbacks a callback to check the manifest hash against an expected value (this is optional, only the property validation callback is required by spec) and if such a callback exists, it gets executed to get the expected/previous stage manifest hash. This hash is then compared to the computed hash, and if it's the same, it then jumps over all the signature checking and chain validation code in the trust evaluation, and notes this for later. (it's implemented as setting a register to 0, where the normal case sets it to 1)


Now you might ask, why would you skip the signature check just because the hash is the same, and couldn't someone forge it? The answer is actually quite simple: Apple wants their devices to boot quickly, and full signature, nonce, and hash checks on every Image4 do take a finite amount of time, however miniscule that time is especially on any of the Apple silicon chips. Apple's intent here is to establish a *chain of trust*, and their logic here is quite simple: If the image being validated is using the same manifest as the previous stage which is assumed to have passed signature validation, then the signature check is entirely redundant and can be skipped. As for it being forged, this is up to the validating program to implement correctly, and iBoot uses the manifest hash it got from the *locked hardware registers* potentially linked to SKP from earlier that ROM sets, so if an attacker has arbitrary read/write in iBoot, it's useless in this case as it won't be able to influence the manifest hash iBoot will mark as expected or not.

As a result of this, the most optimal scenario for an Image4 is using a single manifest where all of the components you expect to use in your bootchain have their digests stored in the manifest that is properly signed, that way validations happen quickly and there isn't need to check signatures repeatedly. This is also part of why mixing and matching manifests for different components isn't exactly convenient. (along with more explicit checks discussed later)

![trust evaluation part 1](/assets/images/image4/trust-eval-part-1.png)

In the case that the manifest hash is not known to be the same as the previous stage's manifest, the next step of the trust evaluation is to perform chain validation (for the RSA4096 SHA384 implementation this is done by `verify_chain_img4_v2`, a wrapper around `verify_chain_img4_v2_with_crack_callback`, which calls back into `crack_chain_rsa4k_sha384` to break up the cert chain, then directly calls `parse_chain` and `parse_extensions` to parse the cert chain up to the root authority for the Image4 implementation, and `verify_chain_signatures` to check that the signature is correct. (this uses the Image4 implementation's signature verification function at offset 0x10)) All parts of this call tree have sanity checks on the arguments as well, and this is why you can't use a fake certificate chain to sign a custom manifest by default.

Once chain validation is done, the manifest properties are then hashed and stored in a dedicated region of the Image4 manifest structure for it, then the next step after that is to actually validate the manifest's signature (the call tree here in the default implementation is `verify_signature_rsa`, which calls into `verify_pkcs1_sig` and after some sanity checking, it calls into `ccrsa_verify_pkcs1v15` which is auditable via the corecrypto source.)

![trust evaluation part 2](/assets/images/image4/trust-eval-part-2.png)

Now that the manifest's signature is considered valid, the trust evaluation parses the manifest properties through `DERImg4DecodeParseManifestProperties` which decodes the manifest properties section and if it's not a manifest only trust evaluation (this is a relatively new idea, this has been used in SEPROM as of newer versions) it then checks if the object type exists in the manifest via `DERImg4DecodeFindProperty` which decodes the manifest to find the object type requested (if it doesn't, it's treated the same as a trust evaluation failure, this is also where it gathers the object properties as well)

![trust evaluation part 3](/assets/images/image4/trust-eval-part-3.png)

Afterwards it evaluates the certificate properties (`Img4DecodeEvaluateCertificateProperties`) to set the constraints based on what the leaf certificate says. (This step is skipped if the manifest hash is the same as previous stage) Coming up on the end, it check if a payload exists and if it does, hashes it in a similar way to how the manifest was hashed and marks the payload hash as valid. The final two steps here are now to iterate through all the manifest properties and the object properties (if not a manifest only trust evaluation) for the specific image being validated to ensure that the image meets the constraints of the platform. (`Img4DecodeEvaluateDictionaryProperties` which is basically just a sanity checked wrapper around the property validation callback that evaluates all the properties that it's given)

![trust evaluation last steps](/assets/images/image4/trust-eval-part-4.png)

### The property validation callback

The property validation callback (which actually is dependent on the Image4 being validated, whether it's an actual image or a local policy) iterates through a list of manifest or object properties depending on what was requested through a list of known properties. Unknown properties are ignored and the callback returns success typically without having any effect (since it might be due to changes in how the signing server operates) Note that for iBoot, the callback is actually wrapped with an interposer to support property capture which is related to that callback check that the parser does. Since there are a lot of tags, I can't explain them all here, but to keep things brief: The property validation callback checks integer properties (SDOM, ECID, security epoch, etc) with either a must be equal or a must be greater-or-equal relation check to ensure the device matches the manifest properties, booleans are checked for if they're true or false in the manifest vs device, and if this mismatches when it isn't expected to (there are some properties that are expected to fail if they aren't present, those force success), property validation will fail. For data properties (mostly DGST for objects and BNCH for the manifest), those use a check where every byte must match, or trust evaluation will fail. 

For the boot nonce/BNCH value, if the local boot flag is set, it will use the BNCN value in the restore info section, and hash it, then use that as the set boot nonce to compare against the manifest, otherwise it will use the nonce and nonce hash iBoot generated. Payload digest is used for comparing the `DGST` value in all cases. Any failure in property validation causes the whole trust evaluation to fail with return value -1. (since the failure isn't in a libImg4Decode component, but rather an iBoot component - and needless to say this property validation callback is implemented differently for different programs) The property validation callback also fills in the state of the object properties.

![property validation callback control flow graph](/assets/images/image4/property-validation-callback-control-flow-graph.png)

Finally, after the property validation callback passes, the trust evaluation itself is successful, however even after the trust evaluation passes, iBoot still does some extra checks. First it takes the digest of the Image4 manifest by calling `Img4DecodeCopyManifestDigest` to copy the manifest hash into a stack register. (likely to save it to store the manifest hash in hardware registers later) Then it checks if the check manifest flag is set (and if mixing and matching manifests is disabled, both have to be true), and if it is, it checks the current manifest hash against the previous stage's manifest hash. (the volatile one, not the hardware locked copy) If it passes, then it checks if effective production/security modes on the object properties (ESEC/EPRO) are what they should be (this replaces the older PROD check for Image3 devices) and then proceeds to check payload properties through a separate function/callback. Once *all* of that is done, *then* iBoot will mark the image as trusted and trust evaluation is considered complete. Mixing and matching different manifests requires that the new manifest have a manifest property titled `AMNM` set to true (this is only attainable to internal Apple employees, there's another local policy mix and match policy tag that is used for external scenarios that enables the same outcome in a different way for Macs)

If trust evaluation fails at any point, iBoot will zero out image properties that depend on image trust, and proceeds to fail the image load. (SecureROM handles this a bit differently, it checks if the SoC is insecure fused *and* if the image load isn't required to be trusted which is controlled by bit 2 of the image load flags (set if board boot config straps are set to test mode), it will pass but mark the image as untrusted (this has no real effect, the real effect comes from zeroing out image properties) - the consequence here is more that untrusted images booted at ROM time *must* be plaintext ARM payloads (and every subsequent stage must also be as it turns out), and the previous manifest hash will be marked as invalid, so the next stage needs to ensure it doesn't rely on that manifest hash being seen as valid.)

### Part 4, cleanup and final steps

Afterwards, the parser then proceeds to optionally decrypt and decompress (in this order), and unwrap the payload in the Image4 to its intended destination. One note is that the decryption code aggressively checks all the keybag sections in the payload to ensure it's encoded correctly, and that the key size is only one of the supported ones, any malformed section will cause it to fail quickly. It then checks a few final things, namely if fuse locking is requested if it's not a local boot (this is always the case except for one edge case in the A8X era) setting the security flag, and if the `EKEY` Image4 property is false (which will be the case for untrusted images and some images that are signed), the parser will set some security subsystem flags that later indicate to the boot transition code that hardware AES keys need to be disabled. Other things checked are if a BPR bit needs to be set (I believe this is done in the restore path somehow?) and if demotion is requested, that security flag is set as well to indicate that demotion needs to be performed, if possible in ROM time.

After that, the image load process is done, the parser's job is complete for the caller to proceed as it wishes.

## How secure is iBoot's Image4 parser?

Image4 parsing at every level in iBoot has been designed to be quite a secure process over the years, and it starts as soon as the caller calls into the Image4 load routines, even ignoring Firebloom. First all pointers used throughout are checked to see if they're not NULL, which mitigates null pointer dereferences as an attack option. Any memory regions used are immediately zeroed when first used so that attackers can't use memory overwrites to influence key security decisions made during Image4 parsing. All the libImg4Decode functions that operate on a section check for the section's explicit existence as noted in the context structure, and the Image4 context structure is built up from scratch during instantiation so that an attacker can't use a pre-prepped context structure to fool the parser. SHA digests are always checked to be the explicit size they have to be (this is nearly always 0x30 bytes these days for SHA-384 but can differ in the future and have differed in the past for SHA-1 devices) so that an attacker can't insert bad data or shellcode through an undersized or oversized hash. Sizes in general tend to be sanity checked a lot. libDER and corecrypto are also quite strong ASN.1 and PKI libraries respectively, with libDER in particular not copying in or trusting input, instead directly decoding it in place as a big security benefit. Corecrypto is also pretty strong and it's cryptographic verification primitives are very simple in practice. Newer devices also benefit from callbacks being protected by PAC. Even after the signature check is done, the keybags, keybag headers and key sizes being checked rigorously by the decryption routine is done to assure that malformed keybags can't lead to memory corruption or shellcode lying in wait. In addition, buffers that are used are always cleared after they are done being used, and in the case of failed validation, the Image4 buffer is zeroed out entirely so that it can't corrupt system state. Overall, iBoot's Image4 parser is quite secure against most of the elementary and first-order attack ideas an attacker could have, and even against more complex attacks it still has a reasonable level of protection against those, especially when paired with Firebloom and the microkernel on modern devices, and the strength of libImg4Decode means the other places that use it will be equally as strong as well.

## A discussion on Image4 patches

As a good way to begin closing out the post, I wanted to discuss a bit on the current state of Image4 patching and propose a new set of patches and guidance that I think work better for the iBoot Image4 parser that "stay true" to the Image4 spec so to speak. (These patches would mostly make sense for people using custom AVPBooter ROMs and patched iBoots for VMApple VMs, or if in the future some iBoot or bootrom vulnerability lets people load custom iBoots in the future on real hardware, or for people using the iPhone 11 emulator)

As of the publication of this blog post, the current "canonical" iBoot Image4 patch is patching the return value of the property validation callback to always return true, and while this is effective a lot of times, in my opinion this patch is pretty flawed for a couple of reasons. The first reason is that this patch doesn't actually allow you to use unsigned or modified manifests at all, the manifest itself still has to be signed with this patch alone, all it does is make the boot nonce and digest checks along with the other checks unconditionally pass, which for many situations is enough, but there are definitely times where you need manifest and image properties to be set a certain way to test alternate code paths, and this patch alone won't help with those scenarios. Furthermore, for those who wish to stress test the Image4 parser, it's important to have a platform on which you can fuzz, and this patch doesn't help with that too much.

The Image4 spec strongly expects that every payload to be executed has a valid manifest for that device, so in line with this, that means the best patches are the ones that make specific checks pass, and not blanket passing everything. I propose the following set of patches for two different scenarios, and I'm happy to hear any feedback on this.

### Scenario 1: someone who wants to use a custom TSS server to sign their own manifests and use their own certificates without patching Image4 validation routines

For this scenario, the best patch is the simplest one, replace the root certificate hardcoded in the Image4 implementation you want to call (the pointer to this root certificate is found in the chain validation function, it's in the callback that's set by that function, for the default implementation it's in `verify_chain_img4_v2`->`crack_chain_rsa4k_sha384`) with your own root certificate (make sure the new root certificate's size is <= the original root certificate's size, for the default implementation this size is `0x55E`, and it is backed by an RSA4096 key pair) 

This scenario is fairly uncommon, but it has a strong upside in that all the Image4 validation and parsing routines will almost certainly work correctly, assuming your leaf certificate is correctly formatted, and you can do a simple pattern match against the root certificate of the CA and replace it with your own as needed, as long as it meets that size constraint. For ECC based implementations (such as the ones used for the local policy, as an extra note, the local policy property validation callback is independent of the normal callback) the cert replacement size should be the same but similar pattern matching should be able to apply. Also, it means that from that stage forward, you should be able to do a complete custom bootchain using purely your own certs.

The downside is that all images sent to an iBoot patched in this way only still need to be signed and personalized, even if you control the signing authority, that's still non-zero friction for doing simple build and test cycles, and it will require a TSS-like authority to be running on a server on your local network to make the process convenient ([micro-tss](https://gitlab.com/turbocooler/micro-tss) is a great starting point to work off of here)


### Scenario 2: someone who wants to load any Image4 with any arbitrary manifest for any device, with the ability to modify the manifest for their device if needed

This scenario requires a few patches. The first patch is going to be to the chain validation function of the Image4 implementation you want to patch (for most cases it will be the RSA4096, SHA384 implementation or the older SHA1, RSA2048 implementation, for the former this function is `verify_chain_img4_v2_with_crack_callback`), replace all the `MOV W0, #0xFFFFFFFF` instructions at the end of the control flow (encoding `00 00 80 12` in hex) with `MOV W0, #0` instructions (encoding `00 00 80 52` in hex) (this should also work for the EC Image4 chain validation functions)

![chain validation RSA patch](/assets/images/image4/chain-validation-patch.png)

The next patch is going to be to signature verification, this one is quite simple, for RSA, replace the `MOV W0, #0xFFFFFFFF` instruction after the `verify_pkcs1_sig` call with a `MOV W0, #0` instruction. For ECDSA it's the exact same, except the `MOV W0, #0xFFFFFFFF` occurs after a CBNZ instead.

![verify patch for RSA](/assets/images/image4/signature-check-patch.png)

The two above patches ensure that you can modify any manifest with any values you want and have it still treated as valid.

The next patchset is a bit more complicated as all are in the property validation callback, this set of patches is for allowing manifests with mismatched values for your devices to still be treated as valid. In the function that validates integer properties (you'll find this by finding an occurrence of a property like `BORD` or `CHIP` before a function call with W0 = 0 or 1 in the property validation callback, this function being called is the one we care about), `NOP` (encoding `1F 20 03 D5` in hex) out all the compare instructions, and replace the `SUB W0, W8, #1` instruction and the `MOV W0, #0xFFFFFFFF` instruction (at least as of iOS 18) with `MOV W0, #0` instructions.

![integer property validation patch](/assets/images/image4/number-relation-patch.png)

The next patch is to the function that validates data properties (found by searching for `BNCH` or `DGST` in a similar way as above), and to explain it in text is a bit complicated so I'll let the image explain it more succinctly than I can.

![matching bytes validation patch](/assets/images/image4/matching-bytes-patch.png)

We are *not* patching the boolean functions here, as those are handled in a weird way so a way to ensure booleans don't hurt this is to apply the currently canonical property validation catchall, however only to the end of the function, replace the last `MOV X0, [register]` instruction with an unconditional `MOV X0, #0` instruction (encoding `00 00 80 D2` in hex)

![property validation catchall patch](/assets/images/image4/prop-validation-catchall.png)

### Mix and match patch

For both scenarios, it is highly recommended (sometimes outright required) to apply this patch as well because it effectively grants you the mix and match capability unconditionally and so any manifest will work, regardless of if it's the same or not.

In `image4_load_with_payload_properties`, after the check for the check manifest flag, there's going to be a `memcmp` of size 0x30 comparing the boot manifest hash to the current manifest hash, patch this to be a `MOV W0, #0`, this should be sufficient to make all manifests pass the mix and match check.

![mix and match patch](/assets/images/image4/mix-n-match-patch.png)

One final note is that not all of the patches are required to be applied if you only need a particular capability, and patches should be applied granularly rather than all at once if not all are needed for your particular use case.

## Conclusion

So we're finally at the end of this very, very long post, I realize this post was quite dense, and I definitely will try to ensure that future posts are not as long, but I really did want to fully explain as much as I could reasonably about my examinations of the Image4 subsystem in iBoot and what it did, so that the iOS field could be furthered and the knowledge base grown and hopefully fill some gaps that public research has so far not documented.

Some of you may have noticed that this post isn't on the Insider Guidebook domain but rather on GitHub Pages (like my old AppleWOA "blog", which no, I did not forget about, I just was unsure how I wanted to continue it), this is because I've decided to commit to using GitHub Pages moving forward (WordPress did not feel super safe to publish my blog on these days due to their lax attitude on security generally in recent years) and I'm in the process of consolidating any of my online blog presence to here. I still hold the Insider Guidebook domain and plan to use it for this site moving forward as well, but for now I haven't yet transferred it off WordPress yet. I'm just using a default GitHub pages template for now while the transition is happening, so this is the new home of the Insider Guidebook moving forward effective the publication of this post.

I almost certainly made mistakes in this post, or left stuff out that could help clarify confusing parts, if you want to give feedback on this post or any ways to improve this blog, please feel free to send me a message on Discord (@amarioguy) or my Fediverse account. ([@amarioguy@treehouse.systems](https://social.treehouse.systems/@amarioguy)) I am also available by [email at armindersingh@theinsiderguidebook.com](mailto:armindersingh@theinsiderguidebook.com) for more formal communication. If you wish to talk securely, I am available on Wire as well (@amarioguy2) and on Signal (I'll give this on request via any of the other methods, as I'm not too comfortable disclosing my Signal alias upfront.)

Anyways, that's all from me for now. Hopefully I'll be back soon, I have a lot more to discuss.
