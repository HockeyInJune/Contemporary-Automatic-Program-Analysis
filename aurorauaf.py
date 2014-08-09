from idautils import *

def main():
    ea = ScreenEA()
    if ea == idaapi.BADADDR:
        print("Could not get get_screen_ea()")
        return

    for funcea in Functions(SegStart(ea), SegEnd(ea)):
        f = idc.Demangle(GetFunctionName(funcea), GetLongPrm(INF_SHORT_DN))
        if (f == None):
            continue
        if (is_copy_constructor(f)):
            #print f
            if ( is_copy_constructor_compiler_generated(funcea) ):
                print f + " looks compiler generated!  Check it out at " + hex(funcea)

def is_copy_constructor_compiler_generated(funcea):
    signature = "\x59\x8b\xfb\xf3\xa5"
    end = FindFuncEnd(funcea)
    buffer = idaapi.get_many_bytes(funcea, end - funcea)
    """
    out = ""
    for b in buffer:
        out += b.encode('hex')
    print out
    """
    if (buffer.find(signature) != -1):
        return True
    else:
        return False

def is_copy_constructor(str):
    length = str.__len__()
    start = 0
    end = length - 1
    separator = str.find("::")
    if (separator == -1):
        return False
    openparen = str.find("(")
    closeparen = str.find(")")
    classname = str[0:separator]
    #print classname
    functionname = str[separator+2:openparen]
    #print functionname
    argument = str[openparen+1:closeparen]
    #print argument
    arguments = argument.split(",")
    firstargument = arguments[0]
    #print firstargument
    space = firstargument.find(" ")
    if (space == -1):
        firstargumenttype = arguments[0]
    else:
        firstargumenttype = arguments[0][0:space]
    #print firstargumenttype
    if (classname == functionname and functionname == firstargumenttype):
        return True
    return False

if __name__ == '__main__':
    main()