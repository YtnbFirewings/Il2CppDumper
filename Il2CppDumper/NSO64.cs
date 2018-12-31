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

        private NSO_HEADER nso_header;
        NSO_SegmentHeader BssSection;
        private List<NSO_SegmentHeader> sections = new List<NSO_SegmentHeader>();

        public static bool IsCompressedNso(String FileName)
        {
            var NsoFile =  File.OpenRead(FileName);

            NsoFile.Seek(0x0C, SeekOrigin.Begin);
            int Flag = NsoFile.ReadByte();

            if ((Flag & 0x7) != 0)
            {
                return true;
            }

            return false;
        }

        public static bool UncompressNso(String inputFileName, String outputFilename)
        {
            var DataSteam = new MemoryStream(File.ReadAllBytes(inputFileName));
            var DataReader = new BinaryReader(DataSteam);
            var header = new NSO_HEADER();

            header.Magic = DataReader.ReadUInt32();
            header.Version = DataReader.ReadUInt32();
            header.Reserved = DataReader.ReadUInt32();
            header.Flags = DataReader.ReadUInt32();


            var isTextCompress = ((header.Flags & 1) != 0);
            var isRoCompress = ((header.Flags & 2) != 0);
            var isDataCompress = ((header.Flags & 4) !=0);

            if (isTextCompress || isRoCompress || isDataCompress)
            {
                header.HeaderText = new NSO_SegmentHeader();
                header.HeaderText.FileOffset = DataReader.ReadInt32();
                header.HeaderText.MemoryOffset = DataReader.ReadInt32();
                header.HeaderText.DecompressedSize = DataReader.ReadInt32();

                header.ModuleOffset = DataReader.ReadInt32();

                header.HeaderRO = new NSO_SegmentHeader();

                header.HeaderRO.FileOffset = DataReader.ReadInt32();
                header.HeaderRO.MemoryOffset = DataReader.ReadInt32();
                header.HeaderRO.DecompressedSize = DataReader.ReadInt32();

                header.ModuleFileSize = DataReader.ReadInt32();

                header.HeaderData = new NSO_SegmentHeader();
                header.HeaderData.FileOffset = DataReader.ReadInt32();
                header.HeaderData.MemoryOffset = DataReader.ReadInt32();
                header.HeaderData.DecompressedSize = DataReader.ReadInt32();

                header.BssSize = DataReader.ReadInt32();

                header.DigestBuildID = DataReader.ReadBytes(0x20);

                header.SizeCompressedText = DataReader.ReadInt32();
                header.SizeCompressedRO = DataReader.ReadInt32();
                header.SizeCompressedData = DataReader.ReadInt32();

                //try decompress
                var savedpos = DataReader.BaseStream.Position;

                byte[] outTextData;
                byte[] outRoData;
                byte[] outDataData;

                if (isTextCompress)
                {
                    DataReader.BaseStream.Position = header.HeaderText.FileOffset;
                    byte[] inTextData = DataReader.ReadBytes(header.SizeCompressedText);
                    outTextData = new byte[header.HeaderText.DecompressedSize];
                    LZ4.LZ4Codec.Decode(inTextData, 0, inTextData.Length, outTextData, 0, outTextData.Length, true);
                }
                else
                {
                    DataReader.BaseStream.Position = header.HeaderText.FileOffset;
                    byte[] inTextData = DataReader.ReadBytes(header.SizeCompressedText);
                    outTextData = inTextData.ToArray();
                }

                if (isRoCompress)
                {
                    DataReader.BaseStream.Position = header.HeaderRO.FileOffset;
                    byte[] inRoData = DataReader.ReadBytes(header.SizeCompressedRO);
                    outRoData = new byte[header.HeaderRO.DecompressedSize];
                    LZ4.LZ4Codec.Decode(inRoData, 0, inRoData.Length, outRoData, 0, outRoData.Length, true);
                }
                else
                {
                    DataReader.BaseStream.Position = header.HeaderRO.FileOffset;
                    byte[] inRoData = DataReader.ReadBytes(header.SizeCompressedRO);
                    outRoData = inRoData.ToArray();
                }

                if (isDataCompress)
                {
                    DataReader.BaseStream.Position = header.HeaderData.FileOffset;
                    byte[] inDataData = DataReader.ReadBytes(header.SizeCompressedData);
                    outDataData = new byte[header.HeaderData.DecompressedSize];
                    LZ4.LZ4Codec.Decode(inDataData, 0, inDataData.Length, outDataData, 0, outDataData.Length, true);
                }
                else
                {
                    DataReader.BaseStream.Position = header.HeaderData.FileOffset;
                    byte[] inDataData = DataReader.ReadBytes(header.SizeCompressedData);
                    outDataData = inDataData.ToArray();                    
                }


                DataReader.BaseStream.Position = savedpos;


                header.Padding = DataReader.ReadBytes(0x1C);


                header.APIInfo = new NSO_RelativeExtent();
                header.APIInfo.RegionRODataOffset = DataReader.ReadInt32();
                header.APIInfo.RegionSize = DataReader.ReadInt32();

                header.DynStr = new NSO_RelativeExtent();
                header.DynStr.RegionRODataOffset = DataReader.ReadInt32();
                header.DynStr.RegionSize = DataReader.ReadInt32();

                header.DynSym = new NSO_RelativeExtent();
                header.DynSym.RegionRODataOffset = DataReader.ReadInt32();
                header.DynSym.RegionSize = DataReader.ReadInt32();

                var outNsoWriter = new BinaryWriter(new FileStream(outputFilename, FileMode.Create));

                header.Flags = 0;
                header.HeaderRO.FileOffset = header.HeaderText.FileOffset + header.HeaderText.DecompressedSize;
                header.HeaderData.FileOffset = header.HeaderRO.FileOffset + header.HeaderRO.DecompressedSize;

                header.SizeCompressedText = header.HeaderText.DecompressedSize;
                header.SizeCompressedRO = header.HeaderRO.DecompressedSize;
                header.SizeCompressedData = header.HeaderData.DecompressedSize;

                outNsoWriter.Write(header.Magic);
                outNsoWriter.Write(header.Version);
                outNsoWriter.Write(header.Reserved);
                outNsoWriter.Write(header.Flags);

                outNsoWriter.Write(header.HeaderText.FileOffset);
                outNsoWriter.Write(header.HeaderText.MemoryOffset);
                outNsoWriter.Write(header.HeaderText.DecompressedSize);
                outNsoWriter.Write(header.ModuleOffset);

                outNsoWriter.Write(header.HeaderRO.FileOffset);
                outNsoWriter.Write(header.HeaderRO.MemoryOffset);
                outNsoWriter.Write(header.HeaderRO.DecompressedSize);
                outNsoWriter.Write(header.ModuleFileSize);

                outNsoWriter.Write(header.HeaderData.FileOffset);
                outNsoWriter.Write(header.HeaderData.MemoryOffset);
                outNsoWriter.Write(header.HeaderData.DecompressedSize);
                outNsoWriter.Write(header.BssSize);

                outNsoWriter.Write(header.DigestBuildID);
                outNsoWriter.Write(header.SizeCompressedText);
                outNsoWriter.Write(header.SizeCompressedRO);
                outNsoWriter.Write(header.SizeCompressedData);

                outNsoWriter.Write(header.Padding);

                outNsoWriter.Write(header.APIInfo.RegionRODataOffset);
                outNsoWriter.Write(header.APIInfo.RegionSize);

                outNsoWriter.Write(header.DynStr.RegionRODataOffset);
                outNsoWriter.Write(header.DynStr.RegionSize);

                outNsoWriter.Write(header.DynSym.RegionRODataOffset);
                outNsoWriter.Write(header.DynSym.RegionSize);

                byte[] ZeroHash = new byte[0x20];
                outNsoWriter.Write(ZeroHash);
                outNsoWriter.Write(ZeroHash);
                outNsoWriter.Write(ZeroHash);

                outNsoWriter.BaseStream.Position = header.HeaderText.FileOffset;

                outNsoWriter.Write(outTextData);
                outNsoWriter.Write(outRoData);
                outNsoWriter.Write(outDataData);
                outNsoWriter.Close();

            }
            else
            {
                return false;
            }
            return true;
        }

        public NSO64(Stream stream, int version, long maxMetadataUsages) : base(stream, version, maxMetadataUsages)
        {


            nso_header = new NSO_HEADER();

            nso_header.Magic = ReadUInt32();
            nso_header.Version = ReadUInt32();
            nso_header.Reserved = ReadUInt32();
            nso_header.Flags = ReadUInt32();


            var isTextCompress = (nso_header.Flags & 1);
            var isRoCompress = (nso_header.Flags & 2);
            var isDataCompress = (nso_header.Flags & 4);



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

        }


        public override dynamic MapVATR(dynamic uiAddr)
        {      
            var section = sections.First(x => ((long)uiAddr) >= x.MemoryOffset && ((long)uiAddr) <= (x.MemoryOffset+x.DecompressedSize));
            return (ulong)((long)(uiAddr) - section.MemoryOffset + section.FileOffset);
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

            return false;
        }

        public override bool SymbolSearch()
        {
            Console.WriteLine("ERROR: This mode not supported.");
            return false;
        }
    }
}
