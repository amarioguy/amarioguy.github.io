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
7. [Conclusion](#conclusion)
8. [Addendum 1: Explaining the evaluate certificate properties step and tying up some loose ends](#addendum-1-explaining-the-evaluate-certificate-properties-step-and-tying-up-some-loose-ends)
9. [Shoutouts and acknowledgements](#shoutouts-and-acknowledgements)


## Prelude: A (hopefully) quick briefer on iBoot and it's position in iDevice security

iBoot is the bootloader used on Apple's ARM platforms. It holds very critical importance in the security model, as many of the security mechanisms on iDevices are actually configured and set up by iBoot (examples of this include CTRR/KIP bounds, PAC key seeds for devices since the A12, and the locations of the Secure Enclave's protected memory regions for its OS, this also applies to devices such as the Vision Pro or Apple silicon Macs.) A compromise in iBoot means that mitigations like CTRR, PAC, MTE (as of the most recent A19 and M5 chips) or TXM can be bypassed, patched, or ignored, and untrusted code can be loaded, which can lead to a malicious or compromised kernel being executed, even the deep sleep handler setup is handled by iBoot so a compromised iBoot could well lead to a more persistent than normal rootkit on iDevices.

iBoot (both as a bootloader in its own right, and in its reduced size ROM form as the bootrom/"SecureROM" of all iDevices since the second gen iPod touch) is also the one responsible for validating every step of the secure boot chain from power-on reset. It ensures that all code in the chain is signed by Apple. To facilitate this, all the raw binary payloads that are part of the secure boot chain (including the kernel) are wrapped in a container format that describes the image as well as holding its signature. On current iDevices (since the iPhone 5S with the A7), this is the Image4 format, and this format and how iBoot parses it will be the central focus of this post. The iBoot images used for analysis in this post will be iBoot-11881.2.10 for the D94AP (iPhone 16 Pro Max), and iBoot-11881.81.2 for the 14-inch M4 Max MacBook Pro (J614cAP) for any Mac-specific notes. (You can follow along with any iBoot image for the 2024 OS releases for any device, as the Image4 library itself is generally device-agnostic. Note that some code differences are because of Firebloom checks being injected by the build process, are a result of different ifdef statements being used for different platforms, or from compiler optimization changes.) Some of the symbols used come from either leftover strings in older iBoots inferred to be the same functions by diffing, come from the same version iBoot in RESEARCH_RELEASE style for the D47AP (iPhone 16), or are symbols I defined myself based on what the function does to the system state or reads from the system.

## What's our threat model?

The threat model here is that the attacker is trying to subvert the secure boot chain and load an unsigned or untrusted image via some type of malformed image uploaded either over USB or implanted into local storage, and the attacker potentially has the capability to write arbitrary memory, but does not yet have code execution in iBoot (which is the attacker's end goal here) so they don't have influence on how the parser itself runs.

## Part 0: The Image4 format

The Image4 format is a quite simple format conceptually, as it's fundamentally just an ASN.1 container over a binary payload. For reference, we're going to be looking at an iBoot Image4, SEP firmware Image4, and a kernelcache Image4 from an M4 Mac mini in reduced security mode in [Lapo Luchini's online ASN.1 parser](https://lapo.it/asn1js/), because OpenSSL is not a fun program to work with and for the purposes of this research, an online ASN.1 decoder and a hex editor are more than enough :)

![iboot image](/assets/images/image4/iboot-image.png)

*Figure 1: iBoot image viewed in the ASN.1 parser.*

As we can see, an Image4 contains a magic number ("IMG4") which lets the program validating this file know that it should try to use Image4 semantics to validate it, as well a couple of SEQUENCE sections. The first one after the magic being a SEQUENCE which has magic "IM4P" as an IA5String. This is an Image4 payload, it's pretty simple conceptually, the other IA5Strings are the tag of the image (we'll see how this is used later) and the version string. The octet string here is the actual binary payload, and the perceptive among you might notice the first 4 bytes in that octet string are the string 'bvx2' which implies a compressed payload, and the sequence after the octet string in the above image describes the uncompressed size. Compression is optional, the payload can be uncompressed and used raw, as-is, in which case the binary payload octet string is the end of the payload, most Apple payloads are compressed as of iOS 15 or so.

One note is that for encrypted images, as seen below, there are also sections below the binary payload octet string that describe the keybags (which are themselves encrypted with either the AP or Secure Enclave's GID key, depending on whether it's the SEP firmware/stage 1 patches or not) and the encryption schema used on the image. (Supported encryption schemes are AES 128, 192, or 256, with 256 being the only value actively used in production payloads.) Encryption is optional, like compression.

Note that since iOS 15, the payload section can canonically contain a section called the "payload properties" section (magic 'PAYP'), this is used in payloads like the kernelcache or the SEP firmware to define additional properties that aren't part of the manifest spec that need to be defined on a per payload basis such as kernel RX/RO regions for SPTM. (The payload properties *are* authenticated by the manifest by virtue of the object payload properties digest value.) In the past, some of these payload properties were stored in an ASN.1 encoded sequence with magic 'IMPL' and shoved into the version string in the IM4P header.
![kernel with payload properties](/assets/images/image4/kernel-payload-properties.png)

*Figure 2: Kernel image in the ASN.1 parser, with focus on payload properties.*

![sep image](/assets/images/image4/sep-image.png)

*Figure 3: SEP image in the ASN.1 parser, with focus on payload properties and keybags.*

The next big sequence has magic "IM4M", this is the manifest, which holds properties for both images it is set to validate against ("object properties" as Apple calls them), and the device or OS itself that the manifest is constrained against ("manifest properties" as Apple says.) This is the only actual "signed" part, as for efficiency and historical reasons (the manifest itself has roots in the older "APTicket" signing scheme used later on for Image3 devices), Apple signs a single binary blob with all the hashes of the bootchain components the manifest evaluates against included (such as boot images, kernelcache, signed system volume root hash as of iOS 15, etc.) This lets Apple speed up image validations as if the manifest being used matches what was used to validate previous bootchain components (this will be explained more later, as it's necessary to understand how the signature/integrity check actually works) all that needs to happen is a simple hash check on the image itself against the digest and it's own properties, instead of having to revalidate the hardware environment against the global manifest properties that apply to all images.

![object properties](/assets/images/image4/object-properties.png)
*Figure 4: iBEC object properties in a manifest.*

One note is that Apple in their firmware restore images actually doesn't ship full Image4 files, since unlike Image3 (which started out as having pre-signed firmware payloads before transitioning to requiring personalization on production devices, in addition to the bootrom intentionally not recognizing APTicket formats for pre-A7 devices), every Image4 file is expected to have a manifest signed by Apple describing the properties of the manifest stitched separately to the raw Image4 payload itself. Since all parts of the bootchain have transitioned to Image4, Apple can now insist on shipping the payloads separately and having the manifest that describes all components signed separately. (This is almost always done by what Apple calls the "Tatsu" server, henceforth referred to in this post as TSS.) This is important in Apple's model, because it means they are foundationally in control of what versions of iOS are authorized to be installed for a particular device. (Most recently with the launch of iOS and iPadOS 26, Apple recently stopped authorizing installations of iOS 18 for devices that support iOS 26, so attempts to restore those versions will fail.)

There is another section of Image4 files that is important later on and is dynamically generated by the restore client (MobileDevice, idevicerestore, etc.) called "restore info" (magic "IM4R"), and it's role is to store a couple of things, all used by boots that come from either SEPROM or SecureROM, namely the raw boot nonce (the manifest contains the boot nonce hash) which is required for local booting, and on newer devices, the ucon/ucer properties that LLB and iBSS require (this is for some TBM that the AP seems to implement on the A16 and newer. Also seems to be in some SEP Image4s?) We'll only be discussing the boot nonce here, but restore info is not just for the boot nonce anymore.

One note that should be mentioned here: an Image4 file is not required to have all of the sections present, and in fact it's very common to see one with only one or two of them. To note the prominent examples of this: Local policies for Mac secure boot and Cryptexes on all devices are basically Image4s that only practically have the manifest section and a unique set of manifest tags that are parsed by iBoot just for local policies. (A separate callback is used to authenticate the manifests for local policies themselves.) Most Image4s signed by the TSS server do not have the restore info section, having only payload and manifest, as restore info only really used for images that are booted by SecureROM or SEPROM. It's even possible to have an Image4 that's purely a payload and nothing else (although this isn't necessarily a practical use case as we'll see later.)

### How does Apple parse Image4 files?

Apple implements Image4 validation slightly differently in each of their boot components that implement Image4 validation (iBoot, SEPROM, AppleImage4 kext, etc.), and differing amounts of input validation are done in these implementations based on the requirements. However, all of them fundamentally wrap around a shared library that all of them include, called `libImg4Decode` by Apple. This shared library is what actually does all of the parsing of the Image4 binary payload itself. 

Of note is that libImg4Decode is built on top of two other libraries that Apple's maintained for a long time now, namely corecrypto (which is made source-available by Apple at [this link](https://developer.apple.com/security), currently it hosts the macOS Sequoia/iOS 18 revisions, but will hopefully be updated to the Tahoe/iOS 26 versions soon) for the cryptographic primitives such as SHA, RSA, ECDSA, etc, and libDER (which was open source for many many versions, but is no longer disclosed by Apple, I suspect for multiple reasons.) libImg4Decode itself and by consequence corecrypto and libDER is shipped with it's symbol names as part of the AppleImage4 kext that Apple ships as part of the Kernel Debug Kit, the version being used as reference here is the one from the macOS Tahoe build 25A353 KDK, the one for the Tahoe release candidate.

The validating program (in this post's case, iBoot) takes the ASN.1 wrapped Image4 payload, manifest, and restore info and instantiates a context structure describing the image as a whole. (The size of this structure has been 0x1C8 bytes for a while, even with additions in recent devices of certain properties.) The below excerpt describing this context structure along with other info is taken from [this PongoOS header](https://github.com/checkra1n/PongoOS/blob/iOS15/src/lib/img4/img4.h), comments are mine and note that this specific context structure is part of libImg4Decode, most known validating programs have program-specific context structures that work as part of their own Image4 validation code.

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

One note here is that all of the actual data in memory is pointed to by DERItem structures. (This is a common structure used in libDER to represent DER-encoded blobs in memory.) The important ones are represented below, comments again mine.

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

One of the big advantages of how libDER handles DERItems is that this architecture permits libDER to simply just ASN.1 decode any DER-formatted object entirely in place without worrying about copying it in or parsing it to its own structures, meaning that there is less implicit trust required in DER decoding binary blobs in memory. This also means that libDER as-is without Firebloom enhancements has a good degree of resistance to buffer overflow attacks or similar attacks that rely on over or under allocating memory by faking the size. It's also quite a small library, meaning it inherently has lower attack surface as a result of that, and it's very easy to integrate into all stages of boot including the SoC bootroms (such as AP SecureROM or SEPROM.)

The strength of libDER makes libImg4Decode strong by proxy (on top of doing its own checks), and corecrypto itself is also a strong PKI library, being used for multiple years across many Apple projects, so the shared Image4 decoding library should be fairly strong by proxy.

One final note, remember how I said that every section of an Image4 is technically optional and not all have to be included?  As a result of that, nothing in libImg4Decode can assume with certainty any of these sections exist, and so every function that deals with one of these sections must first check for the section's existence before being able to do anything regarding that section, and this is indicated by if `payloadRaw` or `manifestRaw` is not a NULL pointer for those sections, and for restore info, it's checked by seeing if the `nonce` DERItem in it's structure is not NULL (again it's not just for the boot nonce anymore though.)

With this context established, we can finally begin examining how iBoot does Image4 parsing in depth. Let's dive in.

## How iBoot parses an Image4, from start to finish

iBoot's Image4 parsing begins when `image_load`, the general function for loading images in iBoot, calls into the function `image4_load_with_payload_properties` to start the process. (this symbol used to be called `image4_load` in older iBoots but got changed in iOS 15 since the concept of payload properties was formalized into the Image4 spec.) This function's first argument is a pointer to an iBoot general image context structure, which contains a couple of important pieces of info. (This image context structure has existed almost since the Image3 format was introduced for 32-bit devices, so a good chunk of this structure is applicable to Image3 devices too.)

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

*Figure 5: Start of iBoot's image4_load_with_payload_properties function.*

Afterwards, it checks the iBoot *general* image context structure, specifically the bit flags field, and it checks bits 2 and 3, with bit 2 representing the image coming from local storage and bit 3 representing whether the Image4 validation should include checking of the nonce hash and writes this to the environment properties structure. (This will be called the "check nonce hash" flag.) Now, some of you might be asking why is nonce hash validation seemingly gated behind a flag and not just... always done? That's a great question and one we will circle back to in a bit, because the answer actually has some ramifications on how the trust chain operates overall. Either way, if bit 3 is set, it reads bit 3 of a hardware register (on the T8140/A18 Pro, this register is `0x3082B8028`) and stores the bit value into the environment properties structure (I'll call this flag the "check manifest flag" for reasons you'll see in a bit.)

(Heuristically, it seems to be used mostly from the perspective of the AP as a place for iBoot to set some flags it uses based on experimentation with the equivalent register on the A11 - seems to lay in PMGR or miniPMGR space typically so I'll call this register the PMGR flags register) 

Bit 2 of the image load flags is also read and the boolean for whether the parser is booting a locally stored image is stored in the environment properties structure (Henceforth, this flag is being called the "local boot" flag), and then it reads another set of hardware registers (for A18 Pro: `0x300730030-0x30073005C` - size `0x30` bytes) to read off a SHA-384 hash that a previous boot stage stored of the previous manifest. (Henceforth this will be called the "previous manifest hash", in the case of SecureROM, this will be 0.) Oddly enough, it seems to do this twice, the second time with a different set of registers that are in a different MMIO space, which seems to check what appears to be a lock bit, and panics if it isn't set. (Inspection of multiple SecureROM binaries for the A11 and later devices that have gotten out over time seems to show that it is the one that writes this lock bit and writes a manifest hash to these different registers, maybe this is related to the [Sealed Key Protection](https://support.apple.com/guide/security/sealed-key-protection-skp-secdc7c6c88e/web) feature Apple notes in their [Platform Security guide](https://support.apple.com/guide/security/welcome/web)? **Update 10/23/2025**: This has been confirmed after some discussion with [@ntrung03](https://github.com/TrungNguyen1909) and other people, along with a closer look at the [PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute/hardwarerootoftrust) and it's mention of the same behavior with the same consequences as SKP.)

Finally, if the check nonce hash bit is set, but the local boot flag is not set (meaning it is not a local boot and the attempted image load is not coming from local storage), it asks the hardware to generate a nonce and later on stores it into another set of hardware registers. (If a nonce has already been generated, it reads that nonce from the hardware registers instead of generating a new one.)

![get nonce call](/assets/images/image4/get-nonce-call.png)

*Figure 6: Image4 load function disassembly showing the get_nonce call.*

![get nonce function](/assets/images/image4/generate-nonce-function.png)

*Figure 7: the get_nonce function disassembly, generating or retrieving a random nonce.*

One more note is that on newer devices (A16 and later), it also reads off a series of registers (A18 Pro: `0x3082C8990`, ends at `0x3082C89AC`), (from some reversing it looks like this set of registers is related to the `SIKA` value in the USB serial number string) and writes that to the environment properties.

Okay, that's a *lot* of hardware stuff read to establish the environment, but finally we can move to actually starting parsing.

### Part 2, initial parsing

Finally moving into actual parsing, iBoot starts by loading the Image4 implementation it needs to use for validation. An "implementation" in this case refers to the set of functions that are used to validate an Image4 that is signed and hashed in a particular way, to a particular signing authority. (For example, the most common implementation in use on iDevices and Macs today is the RSA4096, SHA384 implementation that chains back to the TSS secure boot root certificate authority.) The implementation, quite literally, defines the root of trust the Image4 validator will compare against. One thing to note is that the implementation is actually part of libImg4Decode and *not* iBoot itself, so the implementation will work the same across all software that implements the same version of the Image4 spec. It also means we have the exact symbol names for the implementation, and so we know what actually goes into an implementation. (Chiefly: a function to compute digest, a function to do PKI validation back to the hardcoded root CA for the implementation, a function to verify signature, a function that evaluates properties of the leaf certificate, and OIDs and such.)

![image4 implementation init](/assets/images/image4/init-image4-implementation.png)

*Figure 8: iBoot's function for initializing the default Image4 implementation, used in most cases.*

![image4 implementation, tatsu rsa4096, sha384 implementation](/assets/images/image4/image4-implementation.png)

*Figure 9: the contents of the default Image4 implementation, being viewed in the disassembly of the AppleImage4 kext and by extension, libImg4Decode.*

Note that failures moving forward in any steps will cause the parser to fail the load of the Image4 and exit, while recording the breadcrumb status somehow of why it failed. (iBoot's breadcrumb space for Image4 specific failures is `0x400400xx`, `xx` being the actual reason for failure, with general image load failures being `0x400300xx`) iBoot proper uses an NVRAM variable for this, `boot-breadcrumbs`, in newer versions, while SecureROM will write it to an MMIO register dedicated to storing breadcrumbs.

Next, after calling image4_load_copyobject to copy the image from flash into the destination specified by the caller (which could be the command handler of `go`, for example) in the local storage case (and checking if it's actually a valid Image4 object), it checks an odd edge case, specifically bit 8 of the image load flags. If this is set, it takes a fast path out and just leaves the image in the destination, as-is without any processing and returns success. (I'll call this flag the "skip processing" flag) This flag is very rarely used in practice, only being used during SEP firmware loading (because iBoot's job is just to load the firmware to DRAM, it has separate parsing for the SEP firmware's properties which it has to set, SEPROM is what does the validation itself) and (on newer devices) is related to part of ANS2 firmware load. On Image3 devices, this was used to load the APTicket from flash (because the APTicket was parsed and validated separately in dedicated code for it.) In practice, really this flag won't ever be set on any scenario that matters to most attackers in our threat model.

Moving forward assuming that flag isn't set, after fixing the object size and checking again, it does its first major call into libImg4Decode, specifically `Img4DecodeInit` (which takes the raw Image4 object in X0, the size in X1 and a pointer to where the Image4 general structure should be created in X2). This creates an instance of the Image4 that the other libImg4Decode functions can use to work with the Image4 itself, and effectively sets it up for validation. It does this by zeroing the struct, then throwing the object through the `DERImg4Decode*` functions (the general one, then `DERImg4Decode{Payload, Manifest, RestoreInfo}` in that order) (which are part of libImg4Decode and not libDER proper) which parses the ASN.1 sequences and DER encoded data of each of those sections' headers, and compares the tags to ensure they are looking at the right Image4 section, and then creating the structures for the sections themselves that later functions will consume during Image4 parsing.

![instantiation](/assets/images/image4/image4-instantiation.png)

*Figure 10: iBoot Image4 parser disassembly showing the Img4DecodeInit call.*

![instantiation 2](/assets/images/image4/image4-instantiation-2.png)

*Figure 11: The Img4DecodeInit function.*

Afterwards, the iBoot parser calls `Img4DecodeGetPayloadType` (arguments are img4 context structure in X0 and the pointer to store the type in, in X1) to get the type from the Image4 payload, then optionally sets a callback to capture some properties. (I'm not fully sure when or why this is used, but seems to only be really for certain payload types.) It then checks the type to see if it's a type that the caller will accept (`image_load` passes this in as an argument, 0 is a sentinel value that indicates any type is accepted.) With this, assuming the type is accepted, initial parsing is done and we can move on to the meat of the post, evaluating whether an Image4 is valid and trusted.

### Part 3, trust evaluation

Trust evaluation (this is Apple's term for validating if an image or payload is validly signed and comes from a trusted authority) starts by checking if the Image4 has a manifest via `Img4DecodeManifestExists` (X0 = Image4 structure, X1 = boolean output pointer to write whether the manifest exists or not.) If the manifest doesn't exist, the entire Image4 is treated as if it's untrusted, and this is a really important note to keep in mind, because unlike the Image3 format, there is no concept of an embedded signature to check, if the Image4 doesn't have a valid manifest attached to it, it is not trusted, period. We'll get to how trust evaluation failures are handled in a bit, but keep this in mind.

After validating a manifest exists, if the device doesn't support local policies (older devices don't, newer iDevices do for Cryptexes and Macs support them for secure boot), the next step is the real trust evaluation, but before that, on those newer devices, Apple stores a boolean (1 for Mac iBoots and Cryptex local policy loads on iOS devices, and 0 otherwise) in the environment properties, and this skips a check later (I'll call this the "local policy backed trust evaluation" flag). 

![local policy backed](/assets/images/image4/local-policy-trust-eval-check.png)

*Figure 12: iBoot Image4 parser checking whether an image is authenticated by the default implementation or an implementation backed by local policy.*

Afterwards, on newer devices, it calls a function called `image4_perform_trust_evaluation_with_callbacks` with one of the arguments being a callback list. (More on this later.) This function is essentially a wrapper to perform trust evaluations from a number of implementations to support less secure scenarios. (This is due to how Apple's secure multiboot implementation works on Macs, and this code got ported over to devices that only support Cryptex local policies, albeit with ifdef's that only permit Tatsu-backed authorities to function.)

Alright, now it's time for the real trust evaluation, `Img4DecodePerformTrustEvaluationWithCallbacks` (X0 is the type of the Image4 to evaluate, X1 is the Image4 context structure, X2 is a list of callbacks that need to be run during the trust evaluation, X3 is the Image4 implementation to be used, and X4 is a program specific context structure that the trust evaluation will write into.) This function is the one that does the real heavy lifting here.

(Note that for other programs like the SEPROM, it instead calls `Img4DecodePerformTrustEvaluation` which calls the same underlying function but does more sanitization of the arguments to ensure it's in the right format, it's partly a legacy leftover as the trust evaluation arguments used to differ in the past.) 

Just a note, the screenshots for trust evaluation will be from a SecureROM dump I thoroughly analyzed, as trust evaluation can be quite confusing to parse without these comments due to the number of indirect branches, and this code is more or less the same in the D94 RELEASE iBoot I've been following for most of this post. All failures in this function will return `DR_ParamErr` for the return value.

Trust evaluation starts with a lot of sanity checks to ensure that required callbacks and functions in the Image4 implementation are not NULL, and that the manifest is valid. The first step of the trust evaluation after all these checks is to compute the digest of the raw Image4 manifest (all digests are computed by corecrypto's `ccdigest` function), and assuming that goes without a hitch, it will mark in the Image4 context structure the manifest hash as valid.

![trust evaluation sanity checks](/assets/images/image4/trust-eval-sanity-checks.png)

*Figure 13: start of Img4DecodePerformTrustEvaluationWithCallbacksInternal, being viewed in a SecureROM disassembly.*

Step 2 is to check if the caller gave in the list of callbacks a callback to check the manifest hash against an expected value (this is optional, only the property validation callback is required by spec) and if such a callback exists, it gets executed to get the expected/previous stage manifest hash. This hash is then compared to the computed hash, and if it's the same, it then jumps over all the signature checking and chain validation code in the trust evaluation, and notes this for later. (It's implemented as setting a register to 0, where the normal case sets it to 1.)


Now you might ask, why would you skip the signature check just because the hash is the same, and couldn't someone forge it? The answer is actually quite simple: Apple wants their devices to boot quickly, and full signature, nonce, and hash checks on every Image4 do take a finite amount of time, however miniscule that time is especially on any of the Apple silicon chips. Apple's intent here is to establish a *chain of trust*, and their logic here is quite simple: If the image being validated is using the same manifest as the previous stage which is assumed to have passed signature validation, then the signature check is entirely redundant and can be skipped. As for it being forged, this is up to the validating program to implement correctly, and iBoot uses the manifest hash it got from the *locked hardware registers* ~~potentially linked to~~ used for SKP from earlier that ROM sets, so if an attacker has arbitrary read/write in iBoot, it's useless in this case as it won't be able to influence the manifest hash iBoot will mark as expected or not.

As a result of this, the most optimal scenario for an Image4-based bootchain is using a single manifest where all of the components you expect to use in your bootchain have their digests stored in the manifest that is properly signed, that way validations happen quickly and there isn't need to check signatures repeatedly. This is also part of why mixing and matching manifests for different components isn't exactly convenient (along with more explicit checks discussed later.)

![trust evaluation part 1](/assets/images/image4/trust-eval-part-1.png)

*Figure 14: First part of trust evaluation.*

In the case that the manifest hash is not known to be the same as the previous stage's manifest, the next step of the trust evaluation is to perform chain validation (for the RSA4096 SHA384 implementation this is done by `verify_chain_img4_v2`, a wrapper around `verify_chain_img4_v2_with_crack_callback`, which calls back into `crack_chain_rsa4k_sha384` to break up the cert chain, then directly calls `parse_chain` and `parse_extensions` to parse the cert chain up to the root authority for the Image4 implementation, and `verify_chain_signatures` to check that the signatures are correct for the entire cert chain. (this uses the Image4 implementation's signature verification function at offset 0x10)) All parts of this call tree have sanity checks on the arguments as well, and this is why you can't use a fake certificate chain to sign a custom manifest by default. Note that `parse_extensions` is what actually parses the Image4 constraint set in the leaf certificate, and the chain validation function takes this constraint set and stores it in the "embedded" DERItem, more on this in the addendum at the end of the post. (Arguments for chain validation from the trust evaluation function are cert chain pointer/size in X0 and X1 respectively, X2 and X3 seem to be output pointers for leaf certificate *or* leaf certificate public key (I haven't figured out which it is yet) pointer/size, X4 and X5 are the output pointers for the embedded constraint set in the leaf certificate, X6 is the Image4 implementation, and X7 was initially iBoot-specific Image4 context, however for the RSA4096 default implementation and other implementations, it's overwritten with the function pointer to the function callback that breaks up the certificate chain in the implementation's function itself.)

Once chain validation is done, the manifest properties are then hashed and stored in a dedicated region of the Image4 manifest structure for it, then the next step after that is to actually validate the manifest's signature (the call tree here in the default implementation is `verify_signature_rsa`, which calls into `verify_pkcs1_sig` and after some sanity checking, it calls into `ccrsa_verify_pkcs1v15` which is auditable via the corecrypto source.) (Arguments are X0 and X1 are leaf cert (or leaf cert public key, haven't deduced which it is yet) pointer/size respectively, X2 and X3 are the manifest signature pointer/size, X4 is the manifest *properties* hash, X5 is the hash size, X6 is the Image4 implementation, X7 is iBoot-specific Image4 context.)

![trust evaluation part 2](/assets/images/image4/trust-eval-part-2.png)

*Figure 15: Second part of trust evaluation.*

Now that the manifest's signature is considered valid, the trust evaluation parses the manifest properties through `DERImg4DecodeParseManifestProperties` which decodes the manifest properties section and if it's not a manifest only trust evaluation (this is a relatively new idea, this has been used in SEPROM as of newer versions), it then checks if the object type exists in the manifest via `DERImg4DecodeFindProperty` which decodes the manifest to find the object type requested. (If it doesn't, it's treated the same as a trust evaluation failure, this is also where it gathers the object properties as well.)

![trust evaluation part 3](/assets/images/image4/trust-eval-part-3.png)

*Figure 16: Third part of trust evaluation.*

Afterwards it evaluates the certificate properties (`Img4DecodeEvaluateCertificateProperties`) to set the constraints based on what the leaf certificate says. (This step is skipped if the manifest hash is the same as previous stage) (**Update 10/24/2025**: This is now explained more thoroughly in the [addendum](#addendum-1-explaining-the-evaluate-certificate-properties-step-and-tying-up-some-loose-ends).) Coming up on the end, it checks if a payload exists and if it does, hashes it in a similar way to how the manifest was hashed and marks the payload hash as valid. The final two steps here are now to iterate through all the manifest properties and the object properties (if not a manifest only trust evaluation) for the specific image being validated to ensure that the image meets the constraints of the platform. (`Img4DecodeEvaluateDictionaryProperties` which is basically just a sanity checked wrapper around the property validation callback that evaluates all the properties that it's given)

![trust evaluation last steps](/assets/images/image4/trust-eval-part-4.png)

*Figure 17: Last part of trust evaluation.*

### The property validation callback

The property validation callback (which actually is dependent on the Image4 being validated, whether it's an actual image or a local policy) iterates through a list of manifest or object properties depending on what was requested through a list of known properties. Unknown properties are ignored and the callback returns success typically without having any effect (since it might be due to changes in how the signing server operates, or that not all properties are checked by all validating programs.) Note that for iBoot, the callback is actually wrapped with an interposer to support property capture which is related to that callback check that the parser does. Since there are a lot of tags, I can't explain them all here, but to keep things brief: The property validation callback checks integer properties (SDOM, ECID, security epoch, etc) with either a must be equal or a must be greater-or-equal relation check to ensure the device matches the manifest properties, booleans are checked for if they're true or false in the manifest vs device, and if this mismatches when it isn't expected to, property validation will fail. (There are some properties that are expected to fail if they aren't present or if they aren't set to true, anything expected to fail in such a supported scenario will force success.) For data properties (mostly DGST for objects and BNCH for the manifest), those use a check where every byte must match, or trust evaluation will fail. 

For the boot nonce/BNCH value, if the local boot flag is set, it will use the BNCN value in the restore info section, and hash it, then use that as the set boot nonce to compare against the manifest, otherwise it will use the nonce and nonce hash iBoot generated. (This is why nonce generation by the Image4 parser is gated behind whether the nonce hash needs to be verified as is the case in the non-local boot scenario.) Payload digest is used for comparing the `DGST` value in all cases. Any failure in property validation causes the whole trust evaluation to fail with return value -1. (since the failure isn't in a libImg4Decode component, but rather an iBoot component - and needless to say this property validation callback is implemented differently for different programs) The property validation callback also fills in the state of the object properties.

![property validation callback control flow graph](/assets/images/image4/property-validation-callback-control-flow-graph.png)

*Figure 18: iBoot's property validation callback control flow graph.*

Finally, after the property validation callback passes, the trust evaluation itself is successful, however even after the trust evaluation passes, iBoot still does some extra checks. First it takes the digest of the Image4 manifest by calling `Img4DecodeCopyManifestDigest` to copy the manifest hash into a stack register. (This is likely to save it to store the manifest hash in hardware registers later.) Then it checks if the check manifest flag is set (and if mixing and matching manifests is disabled, both have to be true), and if it is, it checks the current manifest hash against the previous stage's manifest hash. (the volatile one, not the hardware locked copy) If it passes, then it checks if effective production/security modes on the object properties (ESEC/EPRO) are what they should be (this replaces the older PROD check for Image3 devices) and then proceeds to check payload properties through a separate function/callback. Once *all* of that is done, *then* iBoot will mark the image as trusted and trust evaluation is considered complete. Mixing and matching different manifests requires that the new manifest have a manifest property titled `AMNM` set to true (this is only attainable to internal Apple employees, there's another local policy mix and match policy tag that is used for external scenarios that enables the same outcome in a different way for Macs.)

If trust evaluation fails at any point, iBoot will zero out image properties that depend on image trust, and proceeds to fail the image load. (SecureROM handles this a bit differently, it checks if the SoC is insecure fused *and* if the image load isn't required to be trusted which is controlled by bit 2 of the image load flags (set if board boot config straps are set to test mode), it will pass but mark the image as untrusted (this has no real effect, the real effect comes from zeroing out image properties) - the consequence here is more that untrusted images booted at ROM time *must* be plaintext ARM payloads (and every subsequent stage must also be as it turns out), and the previous manifest hash will be marked as invalid, so the next stage needs to ensure it doesn't rely on that manifest hash being seen as valid.)

### Part 4, cleanup and final steps

Afterwards, the parser then proceeds to optionally decrypt and decompress (in this order), and unwrap the payload in the Image4 to its intended destination. One note is that the decryption code aggressively checks all the keybag sections in the payload to ensure it's encoded correctly, and that the key size is only one of the supported ones, any malformed section will cause it to fail quickly. It then checks a few final things, namely if fuse locking is requested if it's not a local boot (this is always the case except for one edge case in the A8X era) setting the security flag, and if the `EKEY` Image4 property is false (which will be the case for untrusted images and some images that are signed), the parser will set some security subsystem flags that later indicate to the boot transition code that hardware AES keys need to be disabled. Other things checked are if a BPR bit needs to be set (I believe this is done in the restore path somehow?) and if demotion is requested, that security flag is set as well to indicate that demotion needs to be performed, if possible in ROM time.

After that, the image load process is done, the parser's job is complete for the caller to proceed as it wishes.

## How secure is iBoot's Image4 parser?

Image4 parsing at every level in iBoot has been designed to be quite a secure process over the years, and it starts as soon as the caller calls into the Image4 load routines, even ignoring Firebloom. First all pointers used throughout are checked to see if they're not NULL, which mitigates null pointer dereferences as an attack option. Any memory regions used are immediately zeroed when first used so that attackers can't use memory overwrites to influence key security decisions made during Image4 parsing. All the libImg4Decode functions that operate on a section check for the section's explicit existence as noted in the context structure, and the Image4 context structure is built up from scratch during instantiation so that an attacker can't use a pre-prepped context structure to fool the parser. SHA digests are always checked to be the explicit size they have to be (this is nearly always 0x30 bytes these days for SHA-384 but can differ in the future and have differed in the past for SHA-1 devices) so that an attacker can't insert bad data or shellcode through an undersized or oversized hash. Sizes in general tend to be sanity checked a lot. libDER and corecrypto are also quite strong ASN.1 and PKI libraries respectively, with libDER in particular not copying in or trusting input, instead directly decoding it in place as a big security benefit. Corecrypto is also pretty strong and it's cryptographic verification primitives are very simple in practice. Newer devices also benefit from callbacks being protected by PAC. Even after the signature check is done, the keybags, keybag headers and key sizes being checked rigorously by the decryption routine is done to assure that malformed keybags can't lead to memory corruption or shellcode lying in wait. In addition, buffers that are used are always cleared after they are done being used, and in the case of failed validation, the Image4 buffer is zeroed out entirely so that it can't corrupt system state. Overall, iBoot's Image4 parser is quite secure against most of the elementary and first-order attack ideas an attacker could have, and even against more complex attacks it still has a reasonable level of protection against those, especially when paired with Firebloom and the microkernel on modern devices, and the strength of libImg4Decode means the other places that use it will be equally as strong as well.

## A discussion on Image4 patches

As a good way to begin closing out the post, I wanted to discuss a bit on the current state of Image4 patching and propose a new set of patches and guidance that I think work better for the iBoot Image4 parser that "stay true" to the Image4 spec so to speak. (These patches would mostly make sense for people using custom AVPBooter ROMs and patched iBoots for VMApple VMs, or if in the future some iBoot or bootrom vulnerability lets people load custom iBoots in the future on real hardware, or for people using the iPhone 11 emulator.)

As of the publication of this blog post, the current "canonical" iBoot Image4 patch is patching the return value of the property validation callback to always return true, and while this is effective a lot of times, in my opinion this patch is pretty flawed for a couple of reasons. The first reason is that this patch doesn't actually allow you to use unsigned or modified manifests at all, the manifest itself still has to be signed with this patch alone, all it does is make the boot nonce and digest checks along with the other checks unconditionally pass, which for many situations is enough, but there are definitely times where you need manifest and image properties to be set a certain way to test alternate code paths, and this patch alone won't help with those scenarios. Furthermore, for those who wish to stress test the Image4 parser, it's important to have a platform on which you can fuzz, and this patch doesn't help with that too much.

The Image4 spec strongly expects that every payload to be executed has a valid manifest for that device, so in line with this, that means the best patches are the ones that make specific checks pass, and not blanket passing everything. I propose the following set of patches for two different scenarios, and I'm happy to hear any feedback on this.

### Scenario 1: someone who wants to use a custom TSS server to sign their own manifests and use their own certificates without patching Image4 validation routines

For this scenario, the best patch is the simplest one, replace the root certificate hardcoded in the Image4 implementation you want to call (the pointer to this root certificate is found in the chain validation function, it's in the callback that's set by that function, for the default implementation it's in `verify_chain_img4_v2`->`crack_chain_rsa4k_sha384`) with your own root certificate (make sure the new root certificate's size is <= the original root certificate's size, for the default implementation this size is `0x55E`, and it is backed by an RSA4096 key pair) 

This scenario is fairly uncommon, but it has a strong upside in that all the Image4 validation and parsing routines will almost certainly work correctly, assuming your leaf certificate is correctly formatted, and you can do a simple pattern match against the root certificate of the CA and replace it with your own as needed, as long as it meets that size constraint. For ECC based implementations (such as the ones used for the local policy, as an extra note, the local policy property validation callback is independent of the normal callback) the cert replacement size should be the same but similar pattern matching should be able to apply. Also, it means that from that stage forward, you should be able to do a complete custom bootchain using purely your own certs.

The downside is that all images sent to an iBoot patched in this way only still need to be signed and personalized, even if you control the signing authority, that's still non-zero friction for doing simple build and test cycles, and it will require a TSS-like authority to be running on a server on your local network to make the process convenient ([micro-tss](https://gitlab.com/turbocooler/micro-tss) is a great starting point to work off of here.)


### Scenario 2: someone who wants to load any Image4 with any arbitrary manifest for any device, with the ability to modify the manifest for their device if needed

This scenario requires a few patches. The first patch is going to be to the chain validation function of the Image4 implementation you want to patch (for most cases it will be the RSA4096, SHA384 implementation or the older SHA1, RSA2048 implementation, for the former this function is `verify_chain_img4_v2_with_crack_callback`), replace all the `MOV W0, #0xFFFFFFFF` instructions at the end of the control flow (encoding `00 00 80 12` in hex) with `MOV W0, #0` instructions (encoding `00 00 80 52` in hex) (this should also work for the EC Image4 chain validation functions)

![chain validation RSA patch](/assets/images/image4/chain-validation-patch.png)

*Figure 19: The end of chain validation, showing where the patch can be made.*

The next patch is going to be to signature verification, this one is quite simple, for RSA, replace the `MOV W0, #0xFFFFFFFF` instruction after the `verify_pkcs1_sig` call with a `MOV W0, #0` instruction. For ECDSA it's the exact same, except the `MOV W0, #0xFFFFFFFF` occurs after a CBNZ instead.

![verify patch for RSA](/assets/images/image4/signature-check-patch.png)

*Figure 20: The signature verification function, showing where the patch can be made.*

The two above patches ensure that you can modify any manifest with any values you want and have it still treated as valid.

The next patchset is a bit more complicated as all are in the property validation callback, this set of patches is for allowing manifests with mismatched values for your devices to still be treated as valid. In the function that validates integer properties (you'll find this by finding an occurrence of a property like `BORD` or `CHIP` before a function call with W0 = 0 or 1 in the property validation callback, this function being called is the one we care about), `NOP` (encoding `1F 20 03 D5` in hex) out all the compare instructions, and replace the `SUB W0, W8, #1` instruction and the `MOV W0, #0xFFFFFFFF` instruction (at least as of iOS 18) with `MOV W0, #0` instructions.

![integer property validation patch](/assets/images/image4/number-relation-patch.png)

*Figure 21: The function in iBoot verifying number properties, showing where the patches are made.*

The next patch is to the function that validates data properties (found by searching for `BNCH` or `DGST` in a similar way as above), and to explain it in text is a bit complicated so I'll let the image explain it more succinctly than I can.

![matching bytes validation patch](/assets/images/image4/matching-bytes-patch.png)

We are *not* patching the boolean functions here, as those are handled in a weird way so a way to ensure booleans don't hurt this is to apply the currently canonical property validation catchall, however only to the end of the function, replace the last `MOV X0, [register]` instruction with an unconditional `MOV X0, #0` instruction (encoding `00 00 80 D2` in hex)

![property validation catchall patch](/assets/images/image4/prop-validation-catchall.png)

*Figure 22: The function in iBoot verifying data properties, showing where the patches are made.*

### Mix and match patch

For both scenarios, it is highly recommended (sometimes outright required) to apply this patch as well because it effectively grants you the mix and match capability unconditionally and so any manifest will work, regardless of if it's the same or not.

In `image4_load_with_payload_properties`, after the check for the check manifest flag, there's going to be a `memcmp` of size 0x30 comparing the boot manifest hash to the current manifest hash, patch this to be a `MOV W0, #0`, this should be sufficient to make all manifests pass the mix and match check.

![mix and match patch](/assets/images/image4/mix-n-match-patch.png)

*Figure 23: The part of iBoot's Image4 parser verifying manifest hashes as being the same, showing where the patch is made.*

One final note is that not all of the patches are required to be applied if you only need a particular capability, and patches should be applied granularly rather than all at once if not all are needed for your particular use case.

## Conclusion

So we're finally at (what used to be) the end of this very, very long post, I realize this post was quite dense, and I definitely will try to ensure that future posts are not as long, but I really did want to fully explain as much as I could reasonably about my examinations of the Image4 subsystem in iBoot and what it did, so that the iOS field could be furthered and the knowledge base grown and hopefully fill some gaps that public research has so far not documented.

Some of you may have noticed that this post isn't on the Insider Guidebook domain but rather on GitHub Pages (like my old AppleWOA "blog", which no, I did not forget about, I just was unsure how I wanted to continue it), this is because I've decided to commit to using GitHub Pages moving forward (WordPress did not feel super safe to publish my blog on these days due to their lax attitude on security generally in recent years) and I'm in the process of consolidating any of my online blog presence to here. I still hold the Insider Guidebook domain and plan to use it for this site moving forward as well, but for now I haven't yet transferred it off WordPress yet. I'm just using a default GitHub pages template for now while the transition is happening, so this is the new home of the Insider Guidebook moving forward effective the publication of this post.

I almost certainly made mistakes in this post, or left stuff out that could help clarify confusing parts, if you want to give feedback on this post or any ways to improve this blog, please feel free to send me a message on Discord (@amarioguy) or my Fediverse account. ([@amarioguy@treehouse.systems](https://social.treehouse.systems/@amarioguy)) I am also available by [email](mailto:armindersingh@theinsiderguidebook.com) for more formal communication. If you wish to talk securely, I am available on Wire as well (@amarioguy2) and on Signal (I'll give this on request via any of the other methods, as I'm not too comfortable disclosing my Signal alias upfront.)

Anyways, that's all from me for now. Hopefully I'll be back soon, I have a lot more to discuss.

## Addendum 1: Explaining the evaluate certificate properties step and tying up some loose ends

As an addendum to this post after getting some good feedback, I figured I'd dive a bit deeper and explain how `Img4DecodeEvaluateCertificateProperties` works, since I only mentioned it a bit lightly in the original post and I figured it deserved a bit more explanation given how important it is in determining not only manifest validity but also in siloing different leaf certificates for different use cases. I'll also be tying up some loose ends that were left behind in the original post. I want to give thanks to [@ntrung03](https://github.com/TrungNguyen1909) for helping me get a foothold in the certificate property evaluation function by giving me a good high-level explanation of it, this addendum would have been a lot harder without his help. As a note, this particular analysis is being done on the same SecureROM dump as was used in the original post to examine trust evaluation.

Before diving in to the certificate property evaluation, we need to look into the certificate chain attached to an Image4 manifest, in particular we need to look at the leaf certificate in said chain, the one that actually signs the manifest itself. Specifically, we need to look at the section with OID 1.2.840.113635.100.6.1.15 (ASN.1 raw hex encoding `2A 86 48 86 F7 63 64 06 01 0F`, the symbol in AppleImage4 is `__oidAppleImg4ManifestCertSpec`, and moving forward I will call this the "Image4 certificate constraint OID")

![verify patch for RSA](/assets/images/image4/leaf-cert-constraints.png)

*Figure 24: Image4 certificate constraint OID section in the ASN.1 parser.*

Notice that this section in the leaf certificate has similar `MANP` and `OBJP` sections with properties (in both the full and reduced security cases) as the actual manifest itself, but some have a `[0]` with a `NULL` nested within them (in the raw ASN.1 encoding in a hex editor, this would be seen as an `A0 02 05 00` after the property name) while others have a `[1]` with `NULL` nested in them (in the raw ASN.1 hex encoding in a hex editor, this is `A1 02 05 00`). In addition to both of these, there's a third type where a `MANP` or `OBJP` property is listed, along with a value specified. This section with this specific OID in the leaf certificate is actually how manifest constraints are implemented and encoded in Image4. (Apple calls these manifest constraints the "RemotePolicy" and describes the three main types of constraints [in the Platform Security guide](https://support.apple.com/guide/security/localpolicy-signing-key-creation-management-sec1f90fbad1/web))

In the leaf certificate, a `[0]` encoding on a given `MANP` or `OBJP` property means that that property must exist in the manifest itself (the value doesn't matter as long as it exists. An example is that most leaf certificates mandate that the `BORD` property must exist in the manifest.) Properties that have a `[1]` encoding are properties that must *not* exist in the manifest, it doesn't matter what their value is, the manifest as a whole will be rejected if a must-not-exist property is found (an example is in the reduced security certificate above, the `ECID` property is marked as must not exist in the leaf cert so no manifests signed with this reduced security leaf cert can have an `ECID` property.) Finally, if a property has a specific value in the constraints section it means that same property in the actual manifest must also have exactly that value. (Most known leaf certificates constrain the `CHIP` property to be a specific value, in effect making each SoC have a unique leaf certificate.) There is a third type of property type that libImg4Decode recognizes called `manx` (it means "manifest property exclude" per a symbol in libImg4Decode supposedly) but to my knowledge no leaf certificate used in production systems has this tag at all, so the purpose of this tag remains an open question for now.

Before diving in, we also need to introduce a few new defines and one new struct into our repertoire, courtesy of [the same PongoOS header](https://github.com/checkra1n/PongoOS/blob/iOS15/src/lib/img4/img4.h) from last time:

```c
#define ASN1_CONSTR_CONT        (ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC) // 0xA000000000000000
#define ASN1_CONSTR_PRIVATE     (ASN1_CONSTRUCTED | ASN1_PRIVATE) // 0xE000000000000000

typedef struct
{
    DERItem content;
    DERTag  tag;
} Img4Property;
```
These defines are used throughout the certificate property evaluation, and also throughout most `DERImg4Decode` prefixed functions, and will be essential to understanding the certificate property evaluation as it relies heavily on these `DERImg4Decode` functions.

With the constraint format and necessary definitions established, we can now pick up from the original post. When chain validation is called during step 3 of the trust evaluation, stored in X4 and X5 are the components of the "embedded" DERItem in the Image4 context structure. After the certificate chain is broken up into its components and parsed in `parse_chain` and `parse_extensions`, the constraint extension DERItem is stored in a context structure specific to that function and then later stored back into the "embedded" DERItem that the chain validation function was passed. Moving forward from that, the next time the "embedded" DERItem is used is in step 7 of trust evaluation, which is when the implementation specific function to evaluate certificate constraints is called (in almost all implementations this function is `Img4DecodeEvaluateCertificateProperties` with X0 = the image4 context structure, X1 being program-specific image4 context.) Let's see what this function actually does.

The first thing this function does (in line with what most of libImg4Decode does) is sanity check its parameters, specifically it checks if X0 is not NULL (aka if it got passed a valid Image4 context structure or not) and that the "embedded" DERItem (which henceforth will be called the "embedded constraint set") in that structure has a nonzero size (meaning the Image4 certificate constraint OID section exists in the leaf certificate.) Of note is that the "embedded" DERItem having zero size will make the function return a `DR_DecodeError` status, and not `DR_Success`, which implies any valid leaf certificate that signs an Image4 manifest must have a constraint set of some kind with the Image4 certificate constraint OID.

After this, it calls `DERDecodeSeqInit` with the embedded constraint set in X0, and two outputs, a pointer to store the DER tag in X1 and a pointer to store the Image4 embedded DER sequence in X2. It then checks if the tag returned was `0x2000000000000011` aka `ASN1_CONSTR_SET`, essentially first checking if the DER sequence decoded was an ASN.1 SET. 

![cert property eval part 1](/assets/images/image4/cert-property-eval-part-1.png)

*Figure 25: First part of certificate property evaluation.*

The function then starts what I'm going to call the "tag finding sequence," where it starts by calling `DERDecodeSeqNext` (X0 = the DER sequence retrieved from before, X1 = the output DERDecodedInfo structure.) to continue decoding the DER sequence. the next thing it checks is if the tag in the DERDecodedInfo is (`ASN1_CONSTR_PRIVATE | {'manx', 'MANP', 'OBJP'}`), if it's none of them, the function will return `DR_UnexpectedTag` (implying that the Image4 certificate constraint OID section must not only exist, but must have valid sections to constrain.)

Starting with the "manifest property exclude" magic, since it's the simplest to explain, it only actually takes any effect if there is a program specific Image4 context, if there is, it loads the data pointer of the embedded constraint set DERDecodedInfo DERItem (basically in code this would be smth like `image4_embedded_DERDecodedInfo.content.data` where "image4_embedded_DERDecodedInfo" is the DERDecodedInfo struct, "content" is the DERItem struct, and "data" being the pointer in that DERItem struct) and stores it in the start of the program specific context. This only seems to be used in some validating programs and not others, iBoot as far as I've seen only really cares about this in one case relating to local policies which are more or less not in scope for this addendum, so for the purposes of this post, this can be ignored.

![cert property eval part 2](/assets/images/image4/cert-property-eval-part-2.png)

*Figure 26: Second part of certificate property evaluation.*

After the tag finding sequence finds either the 'MANP' or 'OBJP' tags in the certificate, it starts what I'm calling the "constraint validation sequence." In the manifest properties ('MANP') case, if this tag is found, it copies the manifest properties DERItem pointer from a saved register to a working register (in the SecureROM dump being used, this is X8.) In the object properties ('OBJP') case, it checks if the Image4 type actually has any object properties in the manifest, and if it does, it proceeds similarly to the manifest properties case, otherwise it continues decoding the top-level sequence. In either case, the function then calls `DERImg4DecodeProperty` (X0 = embedded leaf cert constraints DERItem, X1 = the 'MANP' or 'OBJP' tag, and X2 holding the output of the decode, of type Img4Property as described above). It then checks if the 'MANP' or 'OBJP' section is an ASN.1 SET (with the same type of check as before, checking if the DERTag is equal to `ASN1_CONSTR_SET`, otherwise it returns with `DR_UnexpectedTag`.) If it is a SET, it starts decoding the content of the sequence itself with `DERDecodeSeqContentInit` (X0 is the DERItem, X1 is the output DERSequence that will be used to parse the actual properties in the constraint section) then starts decoding the new sequence (`DERDecodeSeqNext`) to get the tag of the property in the embedded constraints set. It then finds the property with the same tag in the actual manifest or object properties list. (`DERImg4DecodeContentFindItemWithTag`, with X0 being the DERItem, X1 being the tag to find, and X2 being an output pointer that will contain the DERItem found with that tag)

After the item with the tag is found in both the embedded constraints list and the manifest/object properties list, it checks if the property type in the constraint list for the given property and tag is a boolean (0x1), integer (0x2), or an octet string (0x8). If it is, it will check if the type of the tag is less than or equal to IA5String (0x16). (This seems like a redundant check as far as I can tell, but it might be to check that it's not NULL in the constraint set.)

![cert property eval part 3](/assets/images/image4/cert-property-eval-part-3.png)

*Figure 27: Third part of certificate property evaluation.*

In the case where the constraint list tag passed the earlier check of being one of the known types of tags, this is the case where the constraint encodes that the equivalent property in the real property list must be a specific value. It does an additional check to see if finding an item was actually successful (it will fail otherwise), then it checks that the size of both the constraint set property and the manifest/object property are the same (if they're not the same size, they're not the same property.) It then checks the actual value of the property in the manifest itself with the size from before (this is a simple `memcmp` call), and if they're the same, it starts from the top of the constraint validation sequence for the next property in the list, otherwise it fails the evaluation entirely with return value -1.

In the other case, where the tag type in the constraint list is not one of the three known ones, it checks first if the ASN.1 tag is `0xA000000000000000` (`ASN1_CONSTR_CONT` which corresponds to the `[0]` tag in the constraint section we saw earlier) (this is the "property must exist, regardless of its value" check.), If it is, it starts the constraint validation sequence for the next property. Otherwise it checks if the tag is `0xA000000000000001`/`((ASN1_CONSTR_CONT) | 0x1)` (this is the "property must not exist" check and corresponds to the `[1]` tag in the constraint section from earlier.). If it's not this tag, it fails with `DR_UnexpectedTag`. If the tag matches, it then checks if `DERImg4DecodeContentFindItemWithTag` returned that it was the end of the sequence (if W0 = `DR_EndOfSequence`). If it is the end of the sequence, it continues with the constraint validation sequence. If it's not the end of the sequence, it fails the evaluation with `DR_UnexpectedTag`, because the fact that `DERImg4DecodeContentFindItemWithTag` returned that it wasn't the end of the sequence implies the tag exists when it shouldn't exist per the constraint set.

![cert property eval part 4](/assets/images/image4/cert-property-eval-part-4.png)

*Figure 28: Last part of certificate property evaluation, showing the constraint checks.*

After the property list is finished being parsed completely, the constraint validation sequence for the current list completes, and the top level tag checking sequence continues to search for other lists constrained by the Image4 certificate constraints section, and if all lists satisfy the manifest, the function returns `DR_Success` and certificate property evaluation is complete.

Now that we're done explaining certificate property evaluation, let's tie up a few loose ends that were left behind in the original post and provide some updates and future plans. First off, after some discussion with @ntrung03 and other people, along with a closer look at the [PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute/hardwarerootoftrust) which described the same type of behavior seen in SecureROM along with some review of some A10 SEP firmware strings, I can confirm that the lockable hardware registers are indeed linked to Sealed Key Protection, as the behavior is described the same for all three. Apple internally seems to call the feature "Silicon Data Protection," abbreviated as SiDP, and the same SMDK/SMRK terminology is used to describe the keys used as part of SiDP/SKP. 

Next, I fixed some grammar and spelling errors and such in the original post and added some extra argument context for chain validation and signature verification. I've also added figure numbers and captions to the images, and also fixed the table of contents to actually have all the sections, to hopefully make the post a little better and easier to navigate.

Finally, a little bit of thinking about what's next for Image4 itself. As I was digging through the Tahoe variant of the AppleImage4 kext and by extension, the Tahoe variant of libImg4Decode, I noticed some interesting things. Apple as of the 2025 OS releases is beginning to experiment with new Image4 implementations beyond the current RSA and ECC based implementations based on standard certificates. In particular, they've begun to add implementations based on this construct called an "IM4C" or "Image4 Certificate"  which use different chain validation functions (`Img4DecodeVerifyChainIM4C` is the underlying function that does chain validation on all of them) than the traditional manifest types we're more familiar with. While a lot of the IM4C implementations use the standard signature verification functions we're more familiar with, a couple of the implementations are actually verified at least in part using the ML-DSA-87 algorithm, which is a lattice-based PQC signature algorithm standardized by NIST as FIPS 204. ([Here](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) is a link to the NIST paper published in 2024 if you want to read more about ML-DSA-87 if you want to know more about the actual cryptographic primitive, it's a pretty fun read.) Of note is that two of the post-quantum enabled implementations are actually verified using a hybrid scheme where first an RSA4096 signature is checked, followed by the ML-DSA-87 signature. (Apple seems to call this scheme "hybrid scheme3", not fully sure where the 3 comes from though, probably some internal terminology.) There is one implementation that uses pure ML-DSA-87, so that seems to be a supported scenario as well. The post-quantum algorithm primitives in corecrypto used for PQC Image4 authentication are not implemented in the public 2024 corecrypto source at all, so this post-quantum cryptography implementation for Image4s has started to happen or at minimum become more publicly visible with the 2025 OS releases at the earliest. IM4Cs do not seem to be a new construct from some initial digging I did, but I haven't really seen them used in the wild at scale, certainly not on any production device AP secure boot chain I've seen at least, so it seems to mostly have remained an internal or obscure Apple thing for a while now. A fun note is all known root IM4C certificates seem to be the exact same size per the implementations added in the 2025 OS releases. (`0xC39` bytes to be exact)

The implications of corecrypto and libImg4Decode gaining support for post-quantum cryptographic algorithms for Image4 trust evaluation are fairly significant in the long term, because it means the groundwork is being laid *now* for Apple to begin the transition away from the default RSA4096, SHA384 based Image4 implementation for the Apple silicon secure boot chain in use since 2016, and to move to a PQC-based root of trust for future devices. By extension, TSS will likely soon support signing Image4 manifests via PQC algorithms such as ML-DSA-87. The fact that all the post quantum work visible publicly is happening in implementations validated by IM4Cs and not standard certificates at least in the public builds of AppleImage4 seems to suggest that Apple might be leaning towards the entire secure boot chain being validated by IM4C certificates in the future, and that TSS might start signing manifests for future devices with IM4C based leaf certificates rather than standard X.509 certificates. Either way, the increasing risk of a potential future quantum computer that can factor large integers and/or solve the discrete logarithm problem via Shor's algorithm or it's variants (despite my personal opinion that such a computer would likely not materialize at least for the next two decades in practice) and the NIST standardization of lattice-based PQC algorithms means that Apple is in some way preparing to change the root of trust for future devices to be quantum resistant, and for the TSS server to adapt to those changes. (One thing that's worth exploring for anyone who wants to: there's a mirror library to libImg4Decode called `libImg4Encode`, and it's used by Apple in programs that need to emit new Image4 containers and payloads such as the [bless](https://github.com/apple-oss-distributions/bless/blob/465e66732007c5c0d7c20718e5db7627c1665c43/blessUtilities.c#L30) and boot policy utilities on macOS, I believe MobileDevice also has this library due to the need to emit IM4R sections. Is there post-quantum work happening in this library as well? How much can we infer about IM4C creation? Haven't found a good way to get libImg4Encode symbols unfortunately, so please contact me via any of the methods [here](https://amarioguy.github.io/about/) if you find a good symbol source for it for the 2025 OS releases!)

As for my future plans for Image4 research, one of the big things I want to do in the near term regarding Image4 is work on an unofficial, community-based Image4 specification document of some kind. (perhaps with [The Apple Wiki](https://theapplewiki.com/wiki/Main_Page) people? I really want this to be a community-backed spec that's generally accepted while remaining true to how Apple implements the actual spec.) This way, when anyone has questions on the Image4 format in general, the unofficial spec document will be there to explain this. Other than that, I'm not really sure what I want to examine in Image4 at the moment, as I want to orient my research to other parts of iOS for the time being, as well as work more on [AppleWOA](https://github.com/AppleWOA) which has been seeing renewed focus as of late. As for other future plans, I'm really looking to get into more hardware and particularly semiconductor research, expect to see some blog posts in the future about those endeavors. I'm content with this blog post for now though, and I'm happy I got to explain how iBoot's parser works at a deeper level than has been explained in most public research to date.

## Shoutouts and acknowledgements

I don't know why I forgot to include this in the original post, but this work would not have been possible without the help of a lot of people, so I'd like to shout out and acknowledge them here.

- [@ntrung03](https://github.com/TrungNguyen1909) - for helping me out with certificate property evaluation analysis, in addition to helping clarify the SKP registers.
- [@Siguza](https://siguza.net) - for helping me get the blog set up somewhat and helped answer some questions I had on iBoot in the past when I was confused, and whose technical writeups helped inspired this blog in the first place
- [@Cryptiiic](https://github.com/Cryptiiiic) - for helping me understand how the current "canonical" Image4 patch worked and for his 0x8A4 tool for making blob saving for Cryptexes way easier.
- [@Clarity](https://github.com/TheRealClarity) - for helping me proofread this post and fact-check stuff.
- [@AlfieCG](https://alfiecg.uk) - their jailbreak writeup posts also really helped inspire me to write this blog post, they also helped me explore Apple OS reversing from a new perspective.
- [The Apple Wiki](https://theapplewiki.com/wiki/Main_Page) - for providing firmware keys for encrypted firmware components for nearly all OS versions that keys can be fetched for, this is a seriously invaluable resource for any Apple OS researcher.
- The Hack Different community, they've been really helpful in clearing up misconceptions I've had in how parts of Apple's OSes work and have been great in helping me guide my research to this day.
- Anyone else I've forgotten to mention, everyone who helped even a little bit, I greatly appreciate your assistance.

With that, I think that's a good place to close this post out. [Contact me](https://amarioguy.github.io/about/) if you find any extra typos or errors, have any questions on what I discussed on the post, or if you just want to ask me stuff, I'm happy to chat any time.




