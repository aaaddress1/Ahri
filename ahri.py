print('''
 ▄▄▄       ██░ ██  ██▀███   ██▓
▒████▄    ▓██░ ██▒▓██ ▒ ██▒▓██▒
▒██  ▀█▄  ▒██▀▀██░▓██ ░▄█ ▒▒██▒
░██▄▄▄▄██ ░▓█ ░██ ▒██▀▀█▄  ░██░
 ▓█   ▓██▒░▓█▒░██▓░██▓ ▒██▒░██░
 ▒▒   ▓▒█░ ▒ ░░▒░▒░ ▒▓ ░▒▓░░▓  
  ▒   ▒▒ ░ ▒ ░▒░ ░  ░▒ ░ ▒░ ▒ ░
  ░   ▒    ░  ░░ ░  ░░   ░  ▒ ░
      ░  ░ ░  ░  ░   ░      ░  
                               
> Ahri [v1.0] by aaaddress1@chroot.org
''')
targetExe = 'msgbox.exe'
targetExe = input('choose a Win32 (32bit) PE: ')

import r2pipe, pefile, os, struct
from keystone import *


# -------------
# add section (PE), thanks to L4ys
# ref: gist.github.com/L4ys/bfd0b16bf44998f3e6710ad1a13c040f
def align(value, alignment):
    if value % alignment:
        return value + (alignment - value % alignment)
    else:
        return value

def add_section(pe, name, data, characteristics=0xE0000020): # READ | WRITE | EXEC | CODE
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # Remove bound import
    # XXX: only remove bound import when there's no space for section header
    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if directory.name == "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT" and directory.Size:
            # FIXME: remove structs
            pe.set_bytes_at_rva(directory.VirtualAddress, "\x00" * directory.Size)
            directory.Size = 0
            directory.VirtualAddress = 0
            print("[!] Bound Import removed")

    # Check is there enough space for a new section header?
    section_header_size = pe.sections[0].sizeof()
    section_header_end = pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof()

    if (section_header_end + section_header_size) > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise Exception("No enough space for new section header")

    # New section header
    section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__, pe=pe)
    section.set_file_offset(section_header_end)
    section.Name = name.ljust(8, b"\0")
    section.Misc = section.Misc_PhysicalAddress = section.Misc_VirtualSize = len(data)
    section.VirtualAddress = align(pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize, section_alignment)
    section.SizeOfRawData = align(len(data), file_alignment)
    section.PointerToRawData = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    section.PointerToRelocations = 0
    section.PointerToLinenumbers = 0
    section.NumberOfRelocations = 0
    section.NumberOfLinenumbers = 0
    section.Characteristics = characteristics
    section.next_section_virtual_address = None
    pe.sections[-1].next_section_virtual_address = section.VirtualAddress

    # Add new section header
    pe.sections.append(section)
    pe.merge_modified_section_data()
    pe.__structures__.append(section)
    pe.FILE_HEADER.NumberOfSections += 1

    # Append section data
    pe.__data__ = (
        pe.__data__[:section.PointerToRawData].ljust(section.PointerToRawData, b"\x00") + 
        data.ljust(align(len(data), file_alignment), b"\x00") +
        pe.__data__[section.PointerToRawData:]
    )

    # Update SizeOfImage
    pe.OPTIONAL_HEADER.SizeOfImage = align(
        pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize,
        section_alignment
    )

    if section.Characteristics & 0x00000020:
        pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
    if section.Characteristics & 0x00000040:
        pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
    if section.Characteristics & 0x00000080:
        pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    return pe.sections[-1]
# -------------

def asmblr(CODE, dynamicBase):
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE, addr = dynamicBase)
        return bytes(encoding) #(encoding, count)
    except KsError as e:
        print("ERROR: %s" %e)
        return None

rev1= pefile.PE(targetExe)
peImgBase = rev1.OPTIONAL_HEADER.ImageBase
epVA = rev1.OPTIONAL_HEADER.AddressOfEntryPoint
print(f'[+] prefered image base @ {hex(peImgBase)}')
dynamicImg = list( rev1.get_memory_mapped_image(ImageBase = peImgBase) )


r2 = r2pipe.open(targetExe)
r2.cmd('aa')
r2.cmd('aaaaaa')
funcInfoArr = r2.cmdj('afllj')

jitFuncRVA = align(rev1.sections[-1].VirtualAddress + rev1.sections[-1].Misc_VirtualSize, rev1.OPTIONAL_HEADER.SectionAlignment)
jitFuncDB = b''

for funcRecord in funcInfoArr:
    if not 'codexrefs' in funcRecord:
        continue # only interested func xref. 

    dynFuncAddr = funcRecord["offset"]
    funcXrefArr = [ x for x in funcRecord['codexrefs'] if x['at'] == dynFuncAddr ]    
    print(f'[+] current function @ {hex(dynFuncAddr)}')

    for refInfo in funcXrefArr:
        refOpcodeAddr = refInfo["addr"]
        refOpcodeVA = refOpcodeAddr - peImgBase

        if dynamicImg[refOpcodeVA] == 0xe8: # x86 - long call: e8 ?? ?? ?? ??
            
            callerRetRVA = refOpcodeVA + 5
            calleeRVA = dynFuncAddr - peImgBase

            jitFuncDB = jitFuncDB + struct.pack('I', callerRetRVA) + struct.pack('I', calleeRVA)
            print(f'\t[+] got {hex(callerRetRVA)} invoke {hex(calleeRVA)}')
            dynamicImg[refOpcodeVA + 0] = 0xe8
            dynamicImg[refOpcodeVA + 1: refOpcodeVA + 5] = struct.pack('I', jitFuncRVA - (refOpcodeVA + 5))
            #print(f'\t[+] patch x86 long jump at { hex(refOpcodeAddr) }')
    
        else:
            print(f'\t[!] bad ref at: {hex(refOpcodeAddr)} -> {bytes(dynamicImg[refOpcodeVA: refOpcodeVA+5])}')
  

jitFuncOpcode = asmblr('''
    pop dword ptr fs:[0x14]
    push 0xdead
    push 0xbeef

    pushad
    mov ebx,  fs:[0x30]
    mov ebx, [ebx+0x08]

    mov eax, fs:[0x14]
    sub eax, ebx

    .byte 0xe8; .int 0x00;
lookupCallee:
    pop edi
    add edi, database
    sub edi, lookupCallee
    mov ecx, edi
    repne scasd

    xchg esi, edi
    lodsd

    lea eax, [eax+ebx]
    mov dword ptr [esp+0x20], eax
 
    mov eax, fs:[0x14]
    mov dword ptr [esp+0x24], eax
    popad
    ret

jitGarbageCollecc:
    jmp dword ptr fs:[0x14]

database:
    .int 0xdeadbeef
    .int 0x0ea7cafe
''', dynamicBase = 0)

sectAhri = add_section(rev1, b'.ahri',  jitFuncOpcode + jitFuncDB)

modifiedTextSectRaw = dynamicImg[rev1.sections[0].VirtualAddress: rev1.sections[0].VirtualAddress + rev1.sections[0].Misc_VirtualSize]
rev1.set_bytes_at_rva(rev1.sections[0].VirtualAddress, bytes(modifiedTextSectRaw))

rev1.write(filename = targetExe.replace('.exe', '_ahri.exe'))
print('[+] done.')