using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Il2CppDumper
{


    [StructLayout(LayoutKind.Sequential)]

    public class NSO_RelativeExtent
    {
        public int RegionRODataOffset;
        public int RegionSize;
    }

    public class NSO_SegmentHeader
    {
        public int FileOffset;
        public int MemoryOffset;
        public int DecompressedSize;
    }

    public class NSO_HEADER
    {
        // Structure below
        public uint Magic;
        public uint Version;
        public uint Reserved;
        public uint Flags;

        public NSO_SegmentHeader HeaderText;
        public int ModuleOffset;
        public NSO_SegmentHeader HeaderRO;
        public int ModuleFileSize;
        public NSO_SegmentHeader HeaderData;
        public int BssSize;

        public byte[] DigestBuildID;

        public int SizeCompressedText;
        public int SizeCompressedRO;
        public int SizeCompressedData;

        public byte[] Padding;

        public NSO_RelativeExtent APIInfo;
        public NSO_RelativeExtent DynStr;
        public NSO_RelativeExtent DynSym;

        public byte[] HashText;

        public byte[] HashRO;

        public byte[] HashData;
    }

}
