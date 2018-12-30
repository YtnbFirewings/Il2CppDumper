using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace Il2CppDumper
{
    public sealed class NSO64 : Il2Cpp
    {
        //private Elf64_Ehdr elf_header;
        //private Elf64_Phdr[] program_table_element;
        //private Dictionary<string, Elf64_Shdr> sectionWithName = new Dictionary<string, Elf64_Shdr>();

        private NSO_HEADER nso_header;
        //private Dictionary<string, Elf64_Shdr> sectionWithName = new Dictionary<string, Elf64_Shdr>();
        private ulong NsoLoadbase = 0x7100000000;
        NSO_SegmentHeader BssSection;
        private List<NSO_SegmentHeader> sections = new List<NSO_SegmentHeader>();



        public NSO64(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {


            nso_header = new NSO_HEADER();

            nso_header.Magic = ReadUInt32();
            nso_header.Version = ReadUInt32();
            nso_header.Reserved = ReadUInt32();
            nso_header.Flags = ReadUInt32();


            nso_header.HeaderText = new NSO_SegmentHeader();
            nso_header.HeaderText.FileOffset = ReadInt32();
            nso_header.HeaderText.MemoryOffset = ReadInt32();
            nso_header.HeaderText.DecompressedSize = ReadInt32();

            nso_header.ModuleOffset = ReadInt32();

            nso_header.HeaderRO = new NSO_SegmentHeader();

            nso_header.HeaderRO.FileOffset = ReadInt32();
            nso_header.HeaderRO.MemoryOffset = ReadInt32();
            nso_header.HeaderRO.DecompressedSize = ReadInt32();

            nso_header.ModuleFileSize = ReadInt32();

            nso_header.HeaderData = new NSO_SegmentHeader();
            nso_header.HeaderData.FileOffset = ReadInt32();
            nso_header.HeaderData.MemoryOffset = ReadInt32();
            nso_header.HeaderData.DecompressedSize = ReadInt32();

            nso_header.BssSize = ReadInt32();

            nso_header.DigestBuildID = ReadBytes(0x20);

            nso_header.SizeCompressedText = ReadInt32();
            nso_header.SizeCompressedRO = ReadInt32();
            nso_header.SizeCompressedData = ReadInt32();


            nso_header.Padding = ReadBytes(0x1C);


            nso_header.APIInfo = new NSO_RelativeExtent();
            nso_header.APIInfo.RegionRODataOffset = ReadInt32();
            nso_header.APIInfo.RegionSize = ReadInt32();

            nso_header.DynStr = new NSO_RelativeExtent();
            nso_header.DynStr.RegionRODataOffset = ReadInt32();
            nso_header.DynStr.RegionSize = ReadInt32();

            nso_header.DynSym = new NSO_RelativeExtent();
            nso_header.DynSym.RegionRODataOffset = ReadInt32();
            nso_header.DynSym.RegionSize = ReadInt32();

            nso_header.HashText = ReadBytes(0x20);
            nso_header.HashRO = ReadBytes(0x20);
            nso_header.HashData = ReadBytes(0x20);

            sections.Add(nso_header.HeaderText);
            sections.Add(nso_header.HeaderRO);
            sections.Add(nso_header.HeaderData);

            //load M0D0 for BSS Data

            Position = nso_header.HeaderText.FileOffset+4;
            var ModOffset = ReadInt32();
            Position = nso_header.HeaderText.FileOffset + ModOffset;
            if (ReadUInt32() == 0x30444F4D)
            {
                //load bss section info
                var danamicOff = ReadUInt32();
                var bssOff = ReadUInt32();
                var bssEnd = ReadUInt32();

                BssSection = new NSO_SegmentHeader();
                BssSection.DecompressedSize = (int)(bssEnd - bssOff);
                BssSection.MemoryOffset = (int)(bssOff + ModOffset);
                BssSection.FileOffset = BssSection.MemoryOffset;

            }


            /*
            elf_header = new Elf64_Ehdr();
            elf_header.ei_mag = ReadUInt32();
            elf_header.ei_class = ReadByte();
            elf_header.ei_data = ReadByte();
            elf_header.ei_version = ReadByte();
            elf_header.ei_osabi = ReadByte();
            elf_header.ei_abiversion = ReadByte();
            elf_header.ei_pad = ReadBytes(7);
            elf_header.e_type = ReadUInt16();
            elf_header.e_machine = ReadUInt16();
            elf_header.e_version = ReadUInt32();
            elf_header.e_entry = ReadUInt64();
            elf_header.e_phoff = ReadUInt64();
            elf_header.e_shoff = ReadUInt64();
            elf_header.e_flags = ReadUInt32();
            elf_header.e_ehsize = ReadUInt16();
            elf_header.e_phentsize = ReadUInt16();
            elf_header.e_phnum = ReadUInt16();
            elf_header.e_shentsize = ReadUInt16();
            elf_header.e_shnum = ReadUInt16();
            elf_header.e_shtrndx = ReadUInt16();
            program_table_element = ReadClassArray<Elf64_Phdr>(elf_header.e_phoff, elf_header.e_phnum);
            GetSectionWithName();
            RelocationProcessing();
            */
        }

        private void GetSectionWithName()
        {


            /*
            try
            {
                var section_name_off = elf_header.e_shoff + (ulong)elf_header.e_shentsize * elf_header.e_shtrndx;
                Position = section_name_off + 2 * 4 + 8 + 8;//2 * sizeof(Elf64_Word) + sizeof(Elf64_Xword) + sizeof(Elf64_Addr)
                var section_name_block_off = ReadUInt32();
                for (int i = 0; i < elf_header.e_shnum; i++)
                {
                    var section = ReadClass<Elf64_Shdr>(elf_header.e_shoff + elf_header.e_shentsize * (ulong)i);
                    sectionWithName.Add(ReadStringToNull(section_name_block_off + section.sh_name), section);
                }
            }
            catch
            {
                Console.WriteLine("WARNING: Unable to get section.");
            }
            */
        }

        public override dynamic MapVATR(dynamic uiAddr)
        {
            //var program_header_table = program_table_element.First(x => uiAddr >= x.p_vaddr && uiAddr <= x.p_vaddr + x.p_memsz);
            //return uiAddr - (program_header_table.p_vaddr - program_header_table.p_offset);
            try
            {
                for (int i = 0; i < sections.Count; i++)
                {
                    long SectionStart = sections[i].MemoryOffset;
                    long SectionEnd = sections[i].MemoryOffset + sections[i].DecompressedSize;
                    long addr = (long)uiAddr;
                    if (addr >= SectionStart && addr<=SectionEnd )
                    {
                        return (ulong)(addr - SectionStart + sections[i].FileOffset);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: Some errors in MapVATR");

                Console.WriteLine(e.Message);
                //writer.Write("/*");
                //writer.Write($"{e.Message}\n{e.StackTrace}\n");
                //writer.Write("*/\n}\n");
            }
            return 0;
            //var section = sections.First(x => (uiAddr-NsoLoadbase) >= x.MemoryOffset && (uiAddr - NsoLoadbase) <= (x.MemoryOffset+x.DecompressedSize));
        }

        public override bool Search()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        public override bool AdvancedSearch(int methodCount)
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        public override bool PlusSearch(int methodCount, int typeDefinitionsCount)
        {
            ///*
             
            if (true)
            {
                var data = nso_header.HeaderData;
                var text = nso_header.HeaderText;
                var bss = BssSection;

                var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);


                plusSearch.SetSearch(data);
                plusSearch.SetPointerRangeFirst(data);
                plusSearch.SetPointerRangeSecond(text);

                var codeRegistration = plusSearch.FindCodeRegistration64Bit();

                plusSearch.SetPointerRangeSecond(bss);

                var metadataRegistration = plusSearch.FindMetadataRegistration64Bit();

                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init(codeRegistration, metadataRegistration);
                    return true;
                }
            }
            else
            {

                /*
                Console.WriteLine("WARNING: The necessary section is missing.");
                var plusSearch = new PlusSearch(this, methodCount, typeDefinitionsCount, maxMetadataUsages);
                var dataList = new List<Elf64_Phdr>();
                var execList = new List<Elf64_Phdr>();
                foreach (var phdr in program_table_element)
                {
                    if (phdr.p_memsz != 0ul)
                    {
                        switch (phdr.p_flags)
                        {
                            case 1u: //PF_X
                            case 3u:
                            case 5u:
                            case 7u:
                                execList.Add(phdr);
                                break;
                            case 2u: //PF_W && PF_R
                            case 4u:
                            case 6u:
                                dataList.Add(phdr);
                                break;
                        }
                    }
                }
                var data = dataList.ToArray();
                var exec = execList.ToArray();
                plusSearch.SetSearch(data);
                plusSearch.SetPointerRangeFirst(data);
                plusSearch.SetPointerRangeSecond(exec);
                var codeRegistration = plusSearch.FindCodeRegistration64Bit();
                plusSearch.SetPointerRangeSecond(data);
                var metadataRegistration = plusSearch.FindMetadataRegistration64Bit();
                if (codeRegistration != 0 && metadataRegistration != 0)
                {
                    Console.WriteLine("CodeRegistration : {0:x}", codeRegistration);
                    Console.WriteLine("MetadataRegistration : {0:x}", metadataRegistration);
                    Init(codeRegistration, metadataRegistration);
                    return true;
                }
                */
            }
            //*/


            //Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        public override bool SymbolSearch()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }

        private void RelocationProcessing()
        {
            //TODO
            /*if (sectionWithName.ContainsKey(".dynsym") && sectionWithName.ContainsKey(".dynstr") && sectionWithName.ContainsKey(".rela.dyn"))
            {
                Console.WriteLine("Applying relocations...");
                var dynsym = sectionWithName[".dynsym"];
                var symbol_name_block_off = sectionWithName[".dynstr"].sh_offset;
                var rela_dyn = sectionWithName[".rela.dyn"];
                var dynamic_symbol_table = ReadClassArray<Elf64_Sym>(dynsym.sh_offset, (long)dynsym.sh_size / 24);
                var rel_dynend = rela_dyn.sh_offset + rela_dyn.sh_size;
                Position = rela_dyn.sh_offset;
                var writer = new BinaryWriter(BaseStream);
                while ((ulong)Position < rel_dynend)
                {
                    //Elf64_Rela
                    var r_offset = ReadUInt64();
                    //r_info
                    var type = ReadUInt32();
                    var index = ReadUInt32();
                    var r_addend = ReadUInt64();
                    switch (type)
                    {
                        case 257: //R_AARCH64_ABS64
                        //case 1027: //R_AARCH64_RELATIVE
                            {
                                var position = Position;
                                var dynamic_symbol = dynamic_symbol_table[index];
                                writer.BaseStream.Position = (long)r_offset;
                                writer.Write(dynamic_symbol.st_value);
                                Position = position;
                                break;
                            }
                        case 1025: //R_AARCH64_GLOB_DAT
                            {
                                var position = Position;
                                var dynamic_symbol = dynamic_symbol_table[index];
                                var name = ReadStringToNull(symbol_name_block_off + dynamic_symbol.st_name);
                                switch (name)
                                {
                                    case "g_CodeRegistration":
                                        codeRegistration = dynamic_symbol.st_value;
                                        break;
                                    case "g_MetadataRegistration":
                                        metadataRegistration = dynamic_symbol.st_value;
                                        break;
                                }
                                Position = position;
                                break;
                            }
                    }
                }
            }*/
        }
    }
}
