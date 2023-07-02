# What is `mkyar`?

I was looking for awhile for a simple tool that can create [Yara rules](https://yara.readthedocs.io/en/stable/writingrules.html) that can match binary files. I didn't find such tool so I made this one.

# .. but why?

There are many use cases that such tool can enable:

* tamper-proof check of consistency of files
* detect library uses within binaries
* have fun with Yara :)

# How to use:

This runs the tool to generate `test.yar` file of `gping` and then runs the `yara` compiler to execute the rule.

```
$ go run . ~/Downloads/gping > test.yar && yara test.yar ~/Downloads/gping && rm test.
test_name /Users/zinderic/Downloads/gping
$
```

As we can see the rule did match the binary so we successfully and automatically created Yara rule for the file.

Tip: you'll need the [Yara compiler](https://github.com/VirusTotal/yara) or something that can run the rule. The `yara` command in the above example is the Yara compiler.

The `gping` binary file can be any elf (Linux) binary. I used this one in the example - https://github.com/orf/gping/releases/download/gping-v1.12.0/gping-Linux-x86_64.tar.gz. Just make sure to extract the actual binary.

# Future work:

* Add support for MacOS binaries (Mach-O)
* Add support for Windows binaries (PE)
