# What is mkyar?

I was looking for awhile for a simple tool that can create Yara rules that can match binary files. I didn't find such tool so I made this one.

# How to use:

This runs the tool to generate `test.yar` file of `gping` and then runs the `yara` compiler to execute the rule.

```
$ go run . ~/Downloads/gping > test.yar && yara test.yar ~/Downloads/gping && rm test.
test_name /Users/kstaykov/Downloads/gping
$
```

As we can see the rule did match the binary so we successfully and automatically created Yara rule for the file.

# Future work:

* Add support for MacOS binaries (Mach-O)
* Add support for Windows binaries (PE)
