#! python
#
# constgen.py: Generate constants for salsa20 cipher.
#
# AUTHOR(S): objectx
#

import sys, re, os.path, struct

from optparse import OptionParser

# --------------------------------------------------------------

options = None

def show (*args):
    if options.verbose:
        if len (args) < 1:
            print >>sys.stderr, args
        else:
            print >>sys.stderr, args [0] % args [1:]

# --------------------------------------------------------------

def convert (str):
    def obfuscator (x):
        return x ^ options.obfuscate_mask

    def combiner (seq):
        values = []
        for x in seq:
            values.append (x)
            if len (values) == 4:
                yield values
                values = []
        if len (values) != 0:
            yield (values + ['\0', '\0', '\0']) [0:4]

    for v in combiner (str):
        yield obfuscator ((ord (v [0]) <<  0) |
                          (ord (v [1]) <<  8) |
                          (ord (v [2]) << 16) |
                          (ord (v [3]) << 24))

def generate (output, values, var):
    output.write ("const uint32_t\t%s [] = {\n" % var)
    col = 0
    for x in values:
        if col == 0:
            output.write ("   ")
        output.write (" 0x%08X," % x)
        col += 1
        if 4 <= col:
            output.write ("\n")
            col = 0
    if col != 0:
        output.write ("\n")
    output.write ("} ;\n\n")

# --------------------------------------------------------------

def main ():
    global options

    def obfuscate_mask_cb (option, optstr, value, aParser):
        setattr (aParser.values, option.dest, int (value, 0))

    parser = OptionParser ( "usage: %prog [options]")

    parser.set_defaults (output = None, obfuscate_mask = 0x0, verbose = False)

    parser.add_option ("-v", "--verbose", action = "store_true", dest = "verbose", help = "Be verbose.")
    parser.add_option ("-o", "--output", action = "store", type = "string", dest = "output", help = "Specifies output.")
    parser.add_option ("--obfuscate-mask", action = "callback", callback = obfuscate_mask_cb, type="string", dest = "obfuscate_mask", help = "Specifies a mask for value obfuscation.")
    (options, args) = parser.parse_args ()

    def gen (output):
        output.write ("/* --- DO NOT EDIT!  THIS FILE WAS CREATED AUTOMATICALLY --- */\n"
                      "#include \"salsa20.h\"\n"
                      "\n"
                      "namespace Salsa20 {\n"
                      "\n")
        output.write ("const uint32_t\tState::obfuscateMask_ = 0x%08X ;\n\n" % options.obfuscate_mask)
        generate (output, convert ("expand 32-byte k"), "State::sigma_")
        generate (output, convert ("expand 16-byte k"), "State::tau_")
        output.write ("}\t/* End of namespace [Salsa20] */\n")
        output.write ("/* $" "Revision" "$ */\n")
    if not options.output:
        gen (sys.stdout)
    else:
        out = open (options.output, "w")
        try:
            gen (out)
        finally:
            out.close ()
    sys.exit (0)

if __name__ == "__main__":
    main ()
